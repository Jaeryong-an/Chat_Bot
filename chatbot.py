import os, json, time, threading, base64, re
from datetime import datetime, timedelta
from typing import Optional
from functools import lru_cache
import traceback

# ──────────────────────────────────────────────────────────────────────────────
# 1) .env 먼저 로드
# ──────────────────────────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv(dotenv_path=".env", override=False)

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pytz import timezone
JST = timezone("Asia/Tokyo")

# Slack / Bolt
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.http_retry.builtin_handlers import (
    RateLimitErrorRetryHandler,
    ConnectionErrorRetryHandler,
    ServerErrorRetryHandler,
)

# Google
import gspread
from google.oauth2.service_account import Credentials

# Notion/형태소
from janome.tokenizer import Tokenizer

# OpenAI
from openai import OpenAI

# Flask (OAuth 콜백용)
from flask import Flask, request, redirect

# ──────────────────────────────────────────────────────────────────────────────
# 2) 전역 설정
# ──────────────────────────────────────────────────────────────────────────────
DEBUG = os.getenv("DEBUG_GMAIL", "0") == "1"

# ───── Janome singleton ─────
_JANOME = Tokenizer()

# OpenAI 키 적용 (이제 .env 선로드 후에)
OAI = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# 스레드 공유 구조체 보호
user_feedback_sessions = {}
SESS_LOCK = threading.Lock()

# requests 공통 세션 (재시도/타임아웃)
_session = requests.Session()
_retry = Retry(
    total=5,
    connect=5,
    read=5,
    backoff_factor=0.6,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"]),
)
_session.mount("https://", HTTPAdapter(max_retries=_retry))
_session.mount("http://", HTTPAdapter(max_retries=_retry))

def http_get(url, *, params=None, headers=None, auth=None, timeout=20, allow_redirects=True):
    return requests.get(
        url,
        params=params,
        headers=headers,
        auth=auth,              # ← 반드시 전달
        timeout=timeout,
        allow_redirects=allow_redirects,
    )


def http_post(url, **kwargs):
    kwargs.setdefault("timeout", 30)
    return _session.post(url, **kwargs)

# Slack 클라 지연 초기화 + 재시도 핸들러
@lru_cache(maxsize=1)
def get_slack() -> WebClient:
    bot_token = os.getenv("SLACK_BOT_TOKEN")
    if not bot_token:
        raise RuntimeError("SLACK_BOT_TOKEN 환경변수가 없습니다.")
    return WebClient(
        token=bot_token,
        retry_handlers=[
            RateLimitErrorRetryHandler(max_retry_count=5),
            ServerErrorRetryHandler(max_retry_count=5),
            ConnectionErrorRetryHandler(max_retry_count=5),
        ],
    )

# ───── Slack channel id validator ─────
def _channel_id(env_key: str, default: Optional[str] = None) -> Optional[str]:
    val = os.getenv(env_key, default or "")
    if not val:
        return None
    if val.startswith("#"):
        raise RuntimeError(f"{env_key} はチャンネルIDを設定してください（例: C0123456789）")
    return val

def dlog(*args):
    if not DEBUG:
        return
    message = " ".join(str(a) for a in args)
    print("[DBG]", message)
    slack_debug_channel = _channel_id("SLACK_CHANNEL_DEBUG")
    if slack_debug_channel:
        try:
            safe_post_to_slack(get_slack(), channel=slack_debug_channel, text=f"[DBG] {message}")
        except Exception as e:
            print(f"[⚠️ Slackログ送信失敗] {e}")

# ───── Search logging + tokenizer/normalizer ─────
def slog(source: str, **data):
    kv = " ".join(f"{k}={data[k]}" for k in data)
    print(f"[SEARCH] {source} {kv}", flush=True)

# ASCII 전각/반각 변환
def _to_fullwidth_ascii(s: str) -> str:
    return "".join(chr(ord(c)+0xFEE0) if "!" <= c <= "~" else c for c in s)

def _to_halfwidth_ascii(s: str) -> str:
    return "".join(chr(ord(c)-0xFEE0) if "！" <= c <= "～" else c for c in s)

_JP_PUNCT = r"[、。；;：:（）()【】\[\]「」『』｜\|／/・・]+"

def _normalize_query(q: str) -> str:
    q = (q or "").strip()
    q = re.sub(_JP_PUNCT, " ", q)
    q = re.sub(r"\s+", " ", q)
    return q

# 영문·숫자·가나·한자 시퀀스를 그대로 토큰화
_TOKEN_RE = re.compile(
    r"[A-Za-z0-9._-]+|[\u3040-\u309F]+|[\u30A0-\u30FF\u30FC]+|[\u4E00-\u9FFF]+"
)

def _split_terms(text: str):
    if not text:
        return []
    text = _normalize_query(text)
    terms = _TOKEN_RE.findall(text)
    seen, out = set(), []
    for t in terms:
        if t not in seen:
            seen.add(t); out.append(t)
    return out

def safe_post_to_slack(client: WebClient, **kwargs):
    for i in range(5):
        try:
            return client.chat_postMessage(**kwargs)
        except SlackApiError as e:
            # 429 존중
            if e.response.status_code == 429:
                wait = int(e.response.headers.get("Retry-After", "2"))
                time.sleep(wait)
            else:
                print(f"[❌ Slack エラー] {e.response.get('error')} (再試行 {i+1}/5)")
                time.sleep(2 * (i + 1))
        except Exception as e:
            print(f"[⚠️ Slack 通信失敗] {e} (再試行 {i+1}/5)")
            time.sleep(2 * (i + 1))

# ──────────────────────────────────────────────────────────────────────────────
# 3) GSheet 헬퍼 (서비스계정 JSON env 로 단일화)
# ──────────────────────────────────────────────────────────────────────────────
def _extract_sheet_id(raw: str) -> str:
    print(f"[GSheet] _extract input = {repr(raw)}", flush=True)
    s = (raw or "").strip().strip('"').strip("'")
    # URL이면 키만 추출
    m = re.search(r"/spreadsheets/d/([A-Za-z0-9_-]+)", s)
    key = m.group(1) if m else s
    # 허용문자만 남김(제로폭 등 제거)
    key = "".join(ch for ch in key if ch.isalnum() or ch in "-_")
    print(f"[GSheet] _extract output key = {repr(key)}", flush=True)
    if not re.fullmatch(r"[A-Za-z0-9_-]{25,}", key):
        raise RuntimeError(f"GSHEET_ID malformed: {repr(s)} -> {repr(key)}")
    return key

def _gspread_open():
    print(f"[GSheet] env GSHEET_ID = {repr(os.getenv('GSHEET_ID'))}", flush=True)
    raw = os.getenv("GCP_SERVICE_ACCOUNT_JSON", "")
    print(f"[GSheet] SA JSON startswith '{{' ? {raw.lstrip().startswith('{')}", flush=True)
    if not raw:
        raise RuntimeError("GCP_SERVICE_ACCOUNT_JSON empty")
    try:
        data = json.loads(raw) if raw.lstrip().startswith("{") else json.loads(base64.b64decode(raw).decode("utf-8"))
    except Exception:
        data = json.loads(re.sub(r"\r?\n", r"\\n", raw))

    creds = Credentials.from_service_account_info(
        data, scopes=["https://www.googleapis.com/auth/spreadsheets"])
    gc = gspread.authorize(creds)

    sid = _extract_sheet_id(os.getenv("GSHEET_ID"))
    print(f"[GSheet] key={sid!r}", flush=True)
    sh = gc.open_by_key(sid)   # open_by_url 금지
    return gc, sh

def _get_ws(sheet_name: str, headers: Optional[list] = None):
    _, sh = _gspread_open()
    try:
        ws = sh.worksheet(sheet_name)
    except gspread.exceptions.WorksheetNotFound:
        ws = sh.add_worksheet(title=sheet_name, rows=1000, cols=10)
        if headers:
            ws.append_row(headers)
    return ws

# ──────────────────────────────────────────────────────────────────────────────
# 4) GSheet 저장/조회
# ──────────────────────────────────────────────────────────────────────────────
def save_feedback_to_gsheet(faq_id, question, user_id, feedback, comment=""):
    try:
        SHEET_NAME = os.getenv("GSHEET_SHEET", "feedback")
        ws = _get_ws(SHEET_NAME)
        now = datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")
        ws.append_row([now, user_id, faq_id, question, feedback, comment])
        print(f"[✅ GSheet] {faq_id} - {feedback} saved")
    except Exception as e:
        print(f"[❌ GSheet ERROR] {str(e)}")

# ───── gspread safe helpers ─────
def _ws_find_safe(ws, value, *, in_column=1):
    try:
        return ws.find(value, in_column=in_column)
    except Exception:
        return None

def _ws_cell(ws, row, col, default=None):
    try:
        return ws.cell(row, col).value
    except Exception:
        return default

def get_last_history_id(email):
    ws = _get_ws("history", headers=["email", "history_id", "updated_at"])
    cell = _ws_find_safe(ws, email, in_column=1)
    return _ws_cell(ws, cell.row, cell.col + 1) if cell else None

def save_last_history_id(email, history_id):
    ws = _get_ws("history", headers=["email", "history_id", "updated_at"])
    now = datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")
    cell = _ws_find_safe(ws, email, in_column=1)

    prev_id = None
    if not cell:
        ws.append_row([email, str(history_id), now])
    else:
        prev_id = _ws_cell(ws, cell.row, cell.col + 1)
        ws.update_cell(cell.row, cell.col + 1, str(history_id))
        try:
            ws.update_cell(cell.row, cell.col + 2, now)
        except Exception:
            pass

    if str(prev_id or "").strip() != str(history_id).strip():
        print(f"📗 [HISTORY ID] {email} 更新: {history_id}")
        try:
            send_log_to_slack(f"📗 *HISTORY_ID更新: {email}*\n・新しいID: `{history_id}`")
        except Exception as e:
            print(f"[⚠️ Slackログ送信失敗] {e}")

def get_fetch_last_date(email: str) -> Optional[str]:
    ws = _get_ws("fetch_log", headers=["email", "last_date", "updated_at"])
    cell = _ws_find_safe(ws, email, in_column=1)
    return _ws_cell(ws, cell.row, cell.col + 1) if cell else None

def save_fetch_last_date(email, last_date):
    try:
        ws = _get_ws("fetch_log", headers=["email", "last_date", "updated_at"])
        now_str = datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")
        cell = _ws_find_safe(ws, email, in_column=1)
        if cell:
            ws.update_cell(cell.row, cell.col + 1, last_date)
            ws.update_cell(cell.row, cell.col + 2, now_str)
        else:
            ws.append_row([email, last_date, now_str])
    except Exception as e:
        print(f"[❌ fetch_log 更新失敗] {email}: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# 5) Slack 유틸
# ──────────────────────────────────────────────────────────────────────────────
def send_log_to_slack(text, channel=None, title="📘 LOG通知"):
    try:
        client = get_slack()
        channel = channel or _channel_id("SLACK_CHANNEL_LOG")
        if not channel:
            print("⚠️ SLACK_CHANNEL_LOG 未設定のため送信スキップ")
            return
        safe_post_to_slack(
            client,
            channel=channel,
            blocks=[
                {"type":"header","text":{"type":"plain_text","text":title}},
                {"type":"section","text":{"type":"mrkdwn","text":text}},
                {"type":"context","elements":[
                    {"type":"mrkdwn","text":f"`{datetime.now(JST).strftime('%Y-%m-%d %H:%M:%S')}` に送信"}
                ]}
            ]
        )
    except Exception as e:
        print(f"[⚠️ Slackログ送信失敗] {e}")

# ───── Slack search: sentence + keywords, local rerank ─────
def _slack_score(terms, sentence, text):
    nt = _normalize_query(text)
    lc = nt.lower()
    exact = sum(1 for t in terms if t.lower() in lc) * 3
    phrase = 5 if sentence and sentence.lower() in lc else 0
    overlap = len([t for t in terms if t.lower() in lc])
    fuzz = int(10 * overlap / max(1, len(terms)))
    return phrase + exact + fuzz

def _slack_fetch_messages(client, channel_id, max_pages=3, page_size=200):
    msgs = []
    cursor = None
    for _ in range(max_pages):
        resp = client.conversations_history(channel=channel_id, limit=page_size, cursor=cursor)
        chunk = resp.get("messages", []) or []
        msgs.extend(chunk)
        cursor = (resp.get("response_metadata") or {}).get("next_cursor")
        if not cursor or not chunk:
            break
    return msgs

def get_channel_ids_from_env():
    val = os.getenv("SEARCH_CHANNELS_DB", "")
    return [c.strip() for c in val.split(",") if c.strip()]

def search_slack_channels(keyword):
    client = get_slack()
    channels = get_channel_ids_from_env()
    sentence = _normalize_query(keyword)
    terms = _split_terms(keyword)

    slog("slack.query", channels=",".join(channels), sentence=sentence, terms="|".join(terms))

    scored = []
    for cid in channels:
        try:
            for msg in _slack_fetch_messages(client, cid):
                text = msg.get("text") or ""
                if not text.strip():
                    continue
                s = _slack_score(terms, sentence, text)
                if s > 0:
                    scored.append((s, cid, text))
        except Exception as e:
            print(f"❌ Slack検索エラー ({cid}): {e}")

    if not scored:
        return "🙅 Slack内で関連するメッセージが見つかりませんでした。"

    # 정렬 및 중복 제거
    scored.sort(key=lambda x: x[0], reverse=True)
    seen, out = set(), []
    for _, cid, text in scored:
        key = text.strip()[:200]
        if key in seen:
            continue
        seen.add(key)
        out.append(f"📌 <#{cid}>: {text.strip()[:160]}")
        if len(out) >= 10:
            break
    return "\n".join(out)

# ──────────────────────────────────────────────────────────────────────────────
# 6) Gmail 토큰/검색
# ──────────────────────────────────────────────────────────────────────────────
# ───── Gmail search helpers (sentence + keywords + fallback) ─────
def _gmail_queries(keyword: str, label_filter: str):
    sent  = _normalize_query(keyword)
    terms = _split_terms(keyword)
    filt  = ' -in:spam -in:trash' + (f' label:"{label_filter}"' if label_filter else "")
    qs = []
    if sent:
        qs.append(f'"{sent}"{filt}')  # 문장 프레이즈
    if terms:
        qs.append('({}){}'.format(" OR ".join([f'"{t}"' for t in terms]), filt))
        qs.append(f'{" ".join(terms)}{filt}')  # 자유어
    return qs or [filt.strip()]

def _gmail_score(terms, subject, preview):
    txt = _normalize_query(f"{subject} {preview}").lower()
    exact = sum(1 for t in terms if t.lower() in txt) * 3
    overlap = len([t for t in terms if t.lower() in txt])
    fuzz = int(10 * overlap / max(1, len(terms)))
    return exact + fuzz

def refresh_gmail_token_for(refresh_token):
    url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": os.getenv("GMAIL_CLIENT_ID"),
        "client_secret": os.getenv("GMAIL_CLIENT_SECRET"),
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    res = http_post(url, data=data)
    if res.status_code == 200:
        return res.json()["access_token"]
    else:
        print("❌ Token refresh failed:", res.text)
        return None

def _decode_b64_text(data: str) -> str:
    if not data:
        return ""
    # urlsafe のパディング不足対策
    pad = "=" * (-len(data) % 4)
    raw = base64.urlsafe_b64decode((data + pad).encode("ascii"))
    # 代表的な日本語系を順に試行
    for enc in ("utf-8", "iso-2022-jp", "cp932", "euc-jp"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")

def _html_to_text(html: str) -> str:
    s = re.sub(r"(?is)<(script|style).*?</\1>", "", html)
    s = re.sub(r"(?is)<br\s*/?>", "\n", s)
    s = re.sub(r"(?is)</p\s*>", "\n", s)
    s = re.sub(r"(?is)<[^>]+>", " ", s)
    s = re.sub(r"[ \t\f\v]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()

def extract_email_body(payload):
    def find_text_part(parts):
        for part in parts:
            mime = part.get("mimeType", "")
            body_data = part.get("body", {}).get("data", "")
            sub = part.get("parts")
            if mime.startswith("text/plain") and body_data:
                return _decode_b64_text(body_data)
            if sub:
                found = find_text_part(sub)
                if found:
                    return found
        return None

    def find_html_part(parts):
        for part in parts:
            mime = part.get("mimeType", "")
            body_data = part.get("body", {}).get("data", "")
            sub = part.get("parts")
            if mime.startswith("text/html") and body_data:
                return _html_to_text(_decode_b64_text(body_data))
            if sub:
                found = find_html_part(sub)
                if found:
                    return found
        return None

    p = payload.get("payload", {}) or {}
    parts = p.get("parts") or []

    # 1) multipart から text/plain 優先
    if parts:
        txt = find_text_part(parts)
        if txt:
            return txt
        html_txt = find_html_part(parts)
        if html_txt:
            return html_txt

    # 2) 単一 body
    body_data = p.get("body", {}).get("data", "")
    if body_data:
        raw = _decode_b64_text(body_data)
        return _html_to_text(raw) if "<html" in raw.lower() else raw

    # 3) 最後に top-level の text/html を探索
    for part in parts:
        if part.get("mimeType", "").startswith("text/html"):
            data = part.get("body", {}).get("data", "")
            if data:
                return _html_to_text(_decode_b64_text(data))

    return "(本文なし)"

def search_gmail(keyword, refresh_token, max_results=5):
    token = refresh_gmail_token_for(refresh_token)
    if not token:
        return "❌ Gmailアクセストークンの更新に失敗しました。"

    label_filter = os.getenv("GMAIL_LABEL_FILTER", "").strip()
    headers = {"Authorization": f"Bearer {token}"}
    base_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"

    found = []
    used_q = None
    for q in _gmail_queries(keyword, label_filter):
        slog("gmail.query", q=q)
        res = http_get(base_url, headers=headers, params={"q": q, "maxResults": max_results * 4})
        if res.status_code != 200:
            return f"❌ Gmail検索エラー: {res.text}"
        ids = [m.get("id") for m in (res.json().get("messages") or []) if m.get("id")]
        if not ids:
            continue
        used_q = q
        # 상세 조회
        for mid in ids:
            det = http_get(f"{base_url}/{mid}", headers=headers)
            if det.status_code != 200:
                continue
            payload = det.json()
            hdrs = payload.get("payload", {}).get("headers", [])
            subject = sender = date_str = "(不明)"
            for h in hdrs:
                n = h.get("name")
                if n == "Subject": subject = h.get("value", "(不明)")
                elif n == "From":  sender  = h.get("value", "(不明)")
                elif n == "Date":  date_str= h.get("value", "(不明)")
            preview = extract_email_body(payload).strip().replace("\n", " ").replace("\r", "")[:500]
            found.append({"subject": subject, "from": sender, "date": date_str, "preview": preview})
        if found:
            break

    if not found:
        return "📭 メールが見つかりませんでした。"

    # 로컬 재랭킹
    terms = _split_terms(keyword)
    found.sort(key=lambda m: _gmail_score(terms, m["subject"], m["preview"]), reverse=True)

    # 출력
    slog("gmail.used_query", q=used_q or "(none)")
    lines = []
    for m in found[:max_results]:
        lines.append(f"📧 *{m['subject']}*\n送信者: {m['from']}\n")
    return "\n".join(lines)

# ──────────────────────────────────────────────────────────────────────────────
# 7) Notion FAQ 검색
# ──────────────────────────────────────────────────────────────────────────────
# ───── Notion schema helpers ─────
from functools import lru_cache
from difflib import SequenceMatcher

FAQ_TITLE_PROP    = os.getenv("FAQ_TITLE_PROP", "Question")
FAQ_ANSWER_PROP   = os.getenv("FAQ_ANSWER_PROP", "Answer")
FAQ_KEYWORDS_PROP = os.getenv("FAQ_KEYWORDS_PROP", "Keywords")

def _notion_headers():
    return {
        "Authorization": f"Bearer {os.getenv('NOTION_API_TOKEN')}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }

from functools import lru_cache
from difflib import SequenceMatcher

@lru_cache(maxsize=64)
def _notion_props(db_id: str) -> dict:
    r = http_get(f"https://api.notion.com/v1/databases/{db_id}", headers=_notion_headers())
    if r.status_code != 200:
        print(f"❌ Notion DBメタ取得失敗({db_id}): {r.status_code} {r.text[:200]}")
        return {}
    return (r.json() or {}).get("properties", {}) or {}

def _notion_text_props(db_id: str) -> list[str]:
    props = _notion_props(db_id)
    names = []
    for name, meta in (props or {}).items():
        t = meta.get("type")
        if t in ("title", "rich_text"):
            names.append(name)
    return names

def _notion_collect_text(props: dict) -> str:
    title = _get_title(props)
    body = []
    for name, meta in (props or {}).items():
        if isinstance(meta, dict) and meta.get("type") == "rich_text":
            body.append(_notion_plain(meta.get("rich_text", [])))
    return _normalize_query(" ".join([title] + body))

def _has_prop(db_id: str, name: str) -> bool:
    return name in _notion_props(db_id)

def _notion_plain(blocks) -> str:
    if not blocks: return ""
    return "".join((b.get("plain_text") or (b.get("text") or {}).get("content") or "") for b in blocks).strip()

def _get_title(props) -> str:
    p = props.get(FAQ_TITLE_PROP)
    if isinstance(p, dict) and p.get("type") == "title":
        return _notion_plain(p.get("title", [])) or "（タイトルなし）"
    for v in props.values():
        if isinstance(v, dict) and v.get("type") == "title":
            return _notion_plain(v.get("title", [])) or "（タイトルなし）"
    for v in props.values():
        if isinstance(v, dict) and isinstance(v.get("title"), list):
            return _notion_plain(v.get("title")) or "（タイトルなし）"
    return "（タイトルなし）"

def _get_answer(props) -> str:
    p = props.get(FAQ_ANSWER_PROP)
    if isinstance(p, dict):
        t = p.get("type")
        if t == "rich_text":
            return _notion_plain(p.get("rich_text", [])) or "（回答なし）"
        if t == "title":
            return _notion_plain(p.get("title", [])) or "（回答なし）"
    for v in props.values():
        if isinstance(v, dict) and v.get("type") == "rich_text":
            txt = _notion_plain(v.get("rich_text", []))
            if txt: return txt
    for v in props.values():
        if isinstance(v, dict):
            if isinstance(v.get("title"), list):
                txt = _notion_plain(v.get("title"))
                if txt: return txt
            if isinstance(v.get("rich_text"), list):
                txt = _notion_plain(v.get("rich_text"))
                if txt: return txt
    return "（回答なし）"

def extract_keywords_jp(text):
    kws = []
    for t in _JANOME.tokenize(text or ""):
        pos = t.part_of_speech.split(',')[0]
        if pos in ('名詞', '動詞', '形容詞'):
            kws.append(t.base_form)
    return kws

def search_notion_faq(keyword):
    terms = _split_terms(keyword)
    database_ids = os.getenv("FAQ_DATABASE_ID", "").split(",")
    headers = _notion_headers()
    all_results = []

    for db_id in map(str.strip, database_ids):
        if not db_id:
            continue
        text_props = _notion_text_props(db_id)[:6]  # 과대 payload 방지
        if not text_props:
            print(f"⚠️ Notion: text propsなし ({db_id})")
            continue

        # 서버측 OR 필터: 모든 텍스트 속성(title, rich_text)에 대해 contains OR
        or_filters = []
        for t in terms[:8]:
            for p in text_props:
                or_filters.append({"property": p, "rich_text" if p != _get_title.__name__ else "title": {"contains": t}})

        # title도 Notionでは rich_textで検索できるため一律 rich_text に統一
        props_meta = _notion_props(db_id)  # 既存キャッシュ関数
        or_filters = []
        for t in terms[:8]:
            for p in text_props:
                cond = "title" if (props_meta.get(p, {}).get("type") == "title") else "rich_text"
                or_filters.append({"property": p, cond: {"contains": t}})

        payload = {"filter": {"or": or_filters}} if or_filters else {}
        slog("notion.query",
            db_id=db_id,
            props="|".join(text_props),
            terms="|".join(terms),
            filters=len(or_filters))

        r = http_post(f"https://api.notion.com/v1/databases/{db_id}/query",
                    headers=headers, json=payload)
        print(f"[NOTION] status={r.status_code} bytes={len(r.text)}")
        if r.status_code == 200:
            hits = len((r.json() or {}).get("results") or [])
            print(f"[NOTION] hits={hits}")
        else:
            print(f"[NOTION] error-body={r.text[:200]}")

    if not all_results:
        return "🙅 関連するFAQが見つかりませんでした。"

    # 재랭킹: 정확 매치 가중치 + 퍼지 점수
    q_text = _normalize_query(keyword)
    def _score(props):
        txt = _notion_collect_text(props)
        exact = sum(1 for t in terms if t in txt) * 3
        fuzzy = int(100 * SequenceMatcher(None, q_text, txt[:2000]).ratio()) // 10  # 0..10
        return exact + fuzzy

    ranked = sorted(
        ((_score(r.get("properties", {}) or {}), r) for r in all_results),
        key=lambda x: x[0],
        reverse=True
    )
    top = [r for s, r in ranked if s > 0][:5]
    if not top:
        return "🙅 入力内容と類似するFAQが見つかりませんでした。"

    out = []
    for r in top:
        props = r.get("properties", {}) or {}
        title = _get_title(props)
        answer = _get_answer(props)
        out.append(f"📌 *{title}*\n📝 {answer[:200]}{'...' if len(answer) > 200 else ''}")
    return "\n\n".join(out)

# ──────────────────────────────────────────────────────────────────────────────
# 8) Zendesk
# ──────────────────────────────────────────────────────────────────────────────
# ───── Zendesk search helpers (keywords + sentence, fallback, rerank) ─────
_ZDK_PUNCT = r"[、。；;：:（）()【】\[\]「」『』]+"
def _normalize_query_for_zendesk(q: str) -> str:
    q = (q or "").strip()
    q = re.sub(_ZDK_PUNCT, " ", q)
    q = re.sub(r"\s+", " ", q)
    return q

_MIXED_WORD_RE = re.compile(r"[A-Za-z0-9._-]*[\u3040-\u30FF]+[A-Za-z0-9._-]*")

def _to_fullwidth_ascii(s: str) -> str:
    return "".join(chr(ord(c)+0xFEE0) if "!" <= c <= "~" else c for c in s)
def _to_halfwidth_ascii(s: str) -> str:
    return "".join(chr(ord(c)-0xFEE0) if "！" <= c <= "～" else c for c in s)

def _expand_mixed_variants(term: str):
    res = {term}
    res.add(re.sub(r"([A-Za-z0-9._-])([\u3040-\u30FF])", r"\1 \2", term))
    res.add(re.sub(r"([\u3040-\u30FF])([A-Za-z0-9._-])", r"\1 \2", term))
    res.add(_to_fullwidth_ascii(term)); res.add(_to_halfwidth_ascii(term))
    return [t for t in res if t.strip()]

def _zendesk_terms(keyword: str):
    qnorm = _normalize_query_for_zendesk(keyword)
    parts = [t for t in qnorm.split(" ") if t]
    mixed = _MIXED_WORD_RE.findall(qnorm)
    seen, terms = set(), []
    for t in mixed + parts:
        for v in _expand_mixed_variants(t):
            if v not in seen:
                seen.add(v); terms.append(v)
    return terms

# 全角/半角・大文字小文字・ワイルドカードを含めて検索語を拡張
def _zendesk_queries(keyword: str):
    sent  = _normalize_query_for_zendesk(keyword)
    if not sent:
        return []

    # 基本トークン
    base = sent.strip()
    # バリアント
    variants = {
        base,
        base.lower(),
        base.title(),  # 先頭大文字: Criteo
        _to_fullwidth_ascii(base),
        _to_halfwidth_ascii(_to_fullwidth_ascii(base)),
    }
    # ワイルドカードも足す（Zendeskは末尾*対応）
    wc = {v + "*" for v in list(variants) if len(v) >= 3}
    variants |= wc

    # 句として安全にする
    quoted = [f'"{v}"' for v in variants]

    def fields(q: str) -> str:
        return f"subject:{q} OR description:{q} OR comment:{q} OR tags:{q}"

    qs = []
    # ① チケット限定のフレーズ検索（ワイルドカード含む）を最優先
    qs.append("type:ticket (" + " OR ".join(quoted) + ")")

    # ② 各フィールドに対するフレーズ検索
    qs.append("type:ticket (" + " OR ".join(fields(q) for q in quoted) + ")")

    # ③ 自由語OR（フレーズで統一）
    qs.append("type:ticket (" + " OR ".join(quoted) + ")")

    # ④ 最後の保険: type指定なし自由語
    qs.append(sent)

    return qs

import requests

def _zendesk_search_all(url, auth, query, max_pages=3):
    items, page = [], 0
    page_url = None
    base_params = {"query": query, "per_page": 100, "sort_by": "updated_at", "sort_order": "desc"}
    while query and page < max_pages:
        if page_url:
            res = requests.get(page_url, auth=auth, timeout=20)                     # ← 직접 호출
        else:
            res = requests.get(url, auth=auth, params=base_params, timeout=20)      # ← 직접 호출
        if res.status_code != 200:
            slog("zendesk.http_error", code=res.status_code, body=res.text[:300]); break
        payload = res.json() or {}
        items.extend(payload.get("results") or [])
        page_url = payload.get("next_page"); page += 1
        if not page_url: break
    return items

def _ztext(t):
    subj = t.get("subject","") or ""
    desc = t.get("description","") or ""
    tags = " ".join(t.get("tags", []) or [])
    # APIでcommentsを返さないことが多いので安全に無視
    return _normalize_query_for_zendesk(f"{subj} {desc} {tags}")

def search_zendesk_ticket_text(keyword):
    subdomain = os.getenv("ZENDESK_SUBDOMAIN")
    email = os.getenv("ZENDESK_EMAIL")
    token = (os.getenv("ZENDESK_API_TOKEN") or "").strip()
    url = f"https://{subdomain}.zendesk.com/api/v2/search.json"
    auth = (f"{email}/token", token)

    results = []
    for q in _zendesk_queries(keyword):
        slog("zendesk.query", q=q)  # [FIX] 正しい変数名
        try:  # [FIX]
            items = _zendesk_search_all(url, auth, q)
        except Exception as e:  # [FIX]
            import traceback
            slog("zendesk.error", err=str(e), tb=traceback.format_exc())
            items = []
        if items:
            results = items
            break

    if not results:
        return "🙅 チケットが見つかりませんでした。"

    sent = _normalize_query_for_zendesk(keyword).lower()
    terms_lc = [w.lower() for w in _zendesk_terms(keyword)]

    def score(t):
        txt = _ztext(t).lower()
        hit = sum(1 for w in terms_lc if w in txt)
        phrase_bonus = 5 if sent and sent in txt else 0
        fuzz = int(10 * hit / max(1, len(terms_lc)))
        return hit * 3 + fuzz + phrase_bonus

    ranked = sorted(results, key=score, reverse=True)
    return "\n".join(f"#{t.get('id','')} {t.get('subject','(件名不明)')} [status:{t.get('status','?')}]"
                     for t in ranked[:5])

def search_zendesk_ticket_blocks(keyword):
    subdomain = os.getenv("ZENDESK_SUBDOMAIN")
    email = os.getenv("ZENDESK_EMAIL")
    token = (os.getenv("ZENDESK_API_TOKEN") or "").strip()
    url = f"https://{subdomain}.zendesk.com/api/v2/search.json"
    auth = (f"{email}/token", token)

    results = []
    for q in _zendesk_queries(keyword):
        slog("zendesk.query", q=q)  # [FIX]
        try:  # [FIX]
            items = _zendesk_search_all(url, auth, q)
            items = [it for it in items if it.get("result_type") == "ticket"]
        except Exception as e:  # [FIX]
            import traceback
            slog("zendesk.error", err=str(e), tb=traceback.format_exc())
            items = []
        if items:
            results = items
            break

    if not results:
        return [{"type":"section","text":{"type":"mrkdwn","text":"🙅 チケットが見つかりませんでした。"}}]

    terms_lc = [w.lower() for w in _zendesk_terms(keyword)]
    def score(t):
        txt = _ztext(t).lower()
        exact = sum(1 for w in terms_lc if w in txt) * 3
        overlap = len([w for w in terms_lc if w in txt])
        fuzz = int(10 * overlap / max(1, len(terms_lc)))
        return exact + fuzz

    ranked = sorted(results, key=score, reverse=True)

    blocks = [{"type":"section","text":{"type":"mrkdwn","text":"*🎫 Zendesk チケット検索結果:*"}}]
    for t in ranked[:5]:
        tid = t.get("id",""); subject = t.get("subject","(件名不明)"); status = t.get("status","(ステータス不明)")
        turl = f"https://{subdomain}.zendesk.com/agent/tickets/{tid}"
        blocks.append({"type":"section","text":{"type":"mrkdwn","text":f"*<{turl}|#{tid} - {subject}>*\nステータス: `{status}`"}})
        blocks.append({"type":"divider"})
    return blocks

def _zendesk_blocks_to_lines(blocks: list, limit: int = 5):
    rows = []
    for b in blocks:
        if b.get("type") != "section":
            continue
        t = ((b.get("text") or {}).get("text") or "")
        m = re.search(r"\*<([^|>]+)\|\#(\d+)\s-\s(.+?)>\*\nステータス:\s`([^`]+)`", t)
        if m:
            url, tid, subj, status = m.groups()
            rows.append({"id": tid, "subject": subj, "status": status, "url": url})
            if len(rows) >= limit:
                break
    return rows

def _zendesk_lines_to_text(rows):
    return "\n".join(f"#{r['id']} {r['subject']} [status:{r['status']}] <{r['url']}>" for r in rows) \
           or "🙅 チケットが見つかりませんでした。"

def _zendesk_blocks_to_text(blocks: list, limit: int = 5) -> str:
    lines = []
    for b in blocks:
        if b.get("type") != "section":
            continue
        t = ((b.get("text") or {}).get("text") or "")
        # "*<...|#123 - 件名>*\nステータス: `open`" から抽出
        m = re.search(r"\|\#(\d+)\s-\s(.+?)\>\*\nステータス:\s`([^`]+)`", t)
        if m:
            tid, subj, status = m.groups()
            lines.append(f"#{tid} {subj} [status:{status}]")
            if len(lines) >= limit:
                break
    return "\n".join(lines) if lines else "🙅 チケットが見つかりませんでした。"

def _zendesk_boot_healthcheck():
    sub = os.getenv("ZENDESK_SUBDOMAIN")
    email = os.getenv("ZENDESK_EMAIL")
    token = (os.getenv("ZENDESK_API_TOKEN") or "").strip()
    if not sub or not email or not token:
        raise RuntimeError(f"ENV missing for Zendesk: sub={sub!r}, email={email!r}, token={'set' if bool(token) else 'empty'}")

    url = f"https://{sub}.zendesk.com/api/v2/users/me.json"
    r = requests.get(url, auth=(f"{email}/token", token), timeout=15)
    role = ((r.json().get("user") or {}).get("role")) if r.headers.get("content-type","").startswith("application/json") else None
    slog("zendesk.boot", status=r.status_code, role=role, sub=sub, email=email)

    if r.status_code != 200 or role not in ("admin", "agent"):
        raise RuntimeError(f"Zendesk auth failed at boot: status={r.status_code}, role={role}")

def _zendesk_env_guard():
    import re
    sub = os.getenv("ZENDESK_SUBDOMAIN")
    if not sub or sub.lower()=="none" or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", sub):
        raise RuntimeError(f"Invalid ZENDESK_SUBDOMAIN: {sub!r}")

# ──────────────────────────────────────────────────────────────────────────────
# 9) 의도/키워드
# ──────────────────────────────────────────────────────────────────────────────
def detect_intent(text):
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["notion", "faq", "方法", "やり方", "使い方", "できない", "how", "help"]):
        return "FAQ"
    if any(kw in text_lower for kw in ["zendesk", "チケット", "ゼンデスク"]):
        return "チケット"
    if any(kw in text_lower for kw in ["gmail", "メール", "mail", "メール検索"]):
        return "メール"
    return None

def extract_keyword(text, intent):
    # 🔺 "顧客" 오타를 "FAQ"로 수정
    if intent == "FAQ":
        text = re.sub(r"(notion|faq|方法|やり方|使い方|できない|how|help)", "", text, flags=re.I)
    elif intent == "チケット":
        text = re.sub(r"(zendesk|チケット|ゼンデスク)", "", text, flags=re.I)
    elif intent == "メール":
        text = re.sub(r"(gmail|メール|mail|メール検索)", "", text, flags=re.I)
    return text.strip()

# ──────────────────────────────────────────────────────────────────────────────
# 10) Feedback UI
# ──────────────────────────────────────────────────────────────────────────────
def safe_block_text(text, limit=2900):
    if len(text) > limit:
        return text[:limit] + "\n...(省略)"
    return text

def send_faq_with_feedback(say, title, answer, faq_id, corrected_query=None, user=None):
    context_value = f"{faq_id}::{corrected_query or ''}"
    block_text = safe_block_text(
        f"<@{user}> さんへの回答\n"
        f"📌 *{title}*\n"
        f"📝 {answer}"
    )
    blocks = [
        {"type": "section","text": {"type": "mrkdwn","text": block_text}},
        {"type": "actions","elements": [
            {"type": "button","text":{"type":"plain_text","text":"👍 解決"},"style":"primary","action_id":"faq_feedback_yes","value":context_value},
            {"type": "button","text":{"type":"plain_text","text":"👎 未解決"},"style":"danger","action_id":"faq_feedback_no","value":context_value},
        ]}
    ]
    if user:
        return say(text=f"<@{user}> さんへの回答: {title}", blocks=blocks)
    else:
        return say(text=f"{title}", blocks=blocks)

# ──────────────────────────────────────────────────────────────────────────────
# 11) Slack App 초기화 (WebClient 주입)
# ──────────────────────────────────────────────────────────────────────────────
slack_app = App(client=get_slack())
flask_app = Flask(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# 12) Feedback 핸들러
# ──────────────────────────────────────────────────────────────────────────────
@slack_app.action("faq_feedback_yes")
def handle_feedback_yes(ack, body, say):
    ack()
    user = body["user"]["id"]
    value = body["actions"][0]["value"]
    try:
        faq_id, question = value.split("::", 1)
    except ValueError:
        faq_id, question = value, ""
    print(f"[📥 Feedback YES] faq_id={faq_id} question={question}")
    save_feedback_to_gsheet(faq_id, question, user, "yes")
    say("👍 フィードバックありがとうございます！")

def start_feedback_timer(session_key, user_id, faq_id, question, client):
    threading.Thread(
        target=reminder_or_autosave,
        args=(session_key, user_id, faq_id, question, client),
        daemon=True
    ).start()

@slack_app.action("faq_feedback_no")
def handle_feedback_no(ack, body, say, client):
    ack()
    user = body["user"]["id"]
    thread_ts = body.get("message", {}).get("ts")
    value = body["actions"][0]["value"]
    try:
        faq_id, question = value.split("::", 1)
    except ValueError:
        faq_id, question = value, ""

    session_key = f"{user}:{thread_ts}"
    with SESS_LOCK:
        user_feedback_sessions.pop(session_key, None)
        user_feedback_sessions[session_key] = {
            "faq_id": faq_id,
            "question": question,
            "timestamp": time.time()
        }

    start_feedback_timer(session_key, user, faq_id, question, client)
    say(text="ご不明点についてご記入ください。", thread_ts=thread_ts)

def correct_typo_with_gpt(input_text: str) -> str:
    try:
        r = OAI.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content":
                 "あなたは日本語のスペルチェッカーです。\n"
                 "与えられた日本語の文に対して、誤字・脱字・タイプミスのみを修正してください。\n"
                 "文の意味や言い回しは変えないでください。\n"
                 "修正不要ならそのまま返してください。"},
                {"role": "user", "content": input_text}
            ],
            temperature=0
        )
        return r.choices[0].message.content.strip()
    except Exception as e:
        print(f"[❌ 誤字修正失敗] {e}")
        return input_text

def reminder_or_autosave(session_key, user_id, faq_id, question, client):
    time.sleep(600)
    with SESS_LOCK:
        session = user_feedback_sessions.get(session_key)
    if session and session.get("faq_id") == faq_id:
        try:
            save_feedback_to_gsheet(faq_id, question, user_id, "no", comment="コメントなし")
        except Exception as e:
            print(f"❌ Google Sheets 保存失敗: {e}")
        try:
            client.chat_postMessage(
                channel="feedback-momentum",
                text=(f"📝 フィードバック（自動保存）\n"
                      f"*質問:* {question}\n"
                      f"*ユーザー:* <@{user_id}>\n"
                      f"*コメント:* コメントなし")
            )
        except Exception as e:
            print(f"❌ Slack 通知失敗: {e}")
        with SESS_LOCK:
            user_feedback_sessions.pop(session_key, None)

@slack_app.event("message")
def handle_additional_comment(body, say, client):
    event = body.get("event", {})
    user = event.get("user")
    text = event.get("text")
    subtype = event.get("subtype")

    if subtype == "bot_message" or user is None or not text:
        return

    thread_ts = event.get("thread_ts", event.get("ts"))
    session_key = f"{user}:{thread_ts}"

    with SESS_LOCK:
        has_session = session_key in user_feedback_sessions

    if has_session:
        with SESS_LOCK:
            session = user_feedback_sessions.pop(session_key)
        faq_id = session["faq_id"]
        question = session["question"]

        save_feedback_to_gsheet(faq_id, question, user, "no", comment=text)
        client.chat_postMessage(
            channel="feedback-momentum",
            text=(f"📝 フィードバックコメント受信\n"
                  f"*質問:* {question}\n"
                  f"*ユーザー:* <@{user}>\n"
                  f"*コメント:*\n{text}")
        )
        reply_ts = event.get("thread_ts") or event.get("ts")
        say("コメントありがとうございます。内容をチームに共有し、後ほど担当者より返信いたします。", thread_ts=reply_ts)

# ──────────────────────────────────────────────────────────────────────────────
# 13) 멘션 이벤트
# ──────────────────────────────────────────────────────────────────────────────
@slack_app.event("app_mention")
def handle_mention_events(body, say):
    text = body.get("event", {}).get("text", "")
    bot_user_id = body["authorizations"][0]["user_id"]
    user_id = body["event"]["user"]
    clean_text = text.replace(f"<@{bot_user_id}>", "").strip()
    user_query = clean_text

    corrected_query = correct_typo_with_gpt(user_query)
    print(f"[ユーザー入力] {user_query} → [修正後] {corrected_query}")
    print(f"[SEARCH] dispatch sources=notion,zendesk,slack q='{corrected_query}'", flush=True)
    say(text="🔎 検索中です。少々お待ちください...")

    faq_result            = search_notion_faq(corrected_query)
    _z_blocks = search_zendesk_ticket_blocks(corrected_query)
    _z_rows   = _zendesk_blocks_to_lines(_z_blocks)
    zendesk_result_text = _zendesk_lines_to_text(_z_rows)
    slack_result = search_slack_channels(corrected_query) or "🙅 Slack内で関連するメッセージが見つかりませんでした。"
    gmail_result = _search_gmail_first_account(corrected_query) or "📭 メールが見つかりませんでした。"

    print("[SRC] FAQ len:", len(faq_result or ""))
    print("[SRC] ZD  hits:", 0 if (zendesk_result_text or "").startswith("🙅") else len((zendesk_result_text or "").splitlines()))
    print("[SRC] SLK hit?:", not (slack_result or "").startswith("🙅"))
    print("[SRC] GML hit?:", not (gmail_result or "").startswith(("📭","❌")))

    if all(_nohit(x) for x in [faq_result, zendesk_result_text, slack_result, gmail_result]):
        return send_faq_with_feedback(
            say, "AI回答",
            f"該当する情報が見つかりませんでした。\n質問: {corrected_query}\n補足を教えてください。",
            "ai", corrected_query, user=user_id
        )
    has_hit = not all(_nohit(x) for x in [faq_result, zendesk_result_text, slack_result, gmail_result])

    prompt = (
        f"ユーザーからの質問: {corrected_query}\n\n"
        f"以下は関連検索結果（重要度順）。これ『のみ』を根拠に答えること。\n\n"
        f"■ FAQ:\n{faq_result}\n\n"
        f"■ Zendesk(上位):\n{zendesk_result_text}\n\n"
        f"■ Slack:\n{slack_result}\n\n"
        f"■ Gmail:\n{gmail_result}\n\n"
        "要件:\n"
        "- ヒットが1つでもある場合、『見つかりませんでした／情報が不十分』とは書かない。\n"
        "- 最も関連する事実を2〜3文で要約。Zendeskは #ID と件名を明記し、可能ならURLも示す。\n"
        "- 足りない点があるなら、次の具体アクション（参照すべきチケットIDや連絡先）を1つ提案。\n"
    )
    try:
        r = OAI.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system","content": (
                    "あなたはSlack上で動作するアシスタントボットです。\n"
                    "ユーザーの質問に対して、以下の複数の情報源（FAQ、Zendesk、Slack過去投稿）を参照し、"
                    "最も信頼性が高く、関連性のある回答を日本語で作成してください。\n"
                    "回答は2〜3文程度の丁寧で簡潔な表現とし、"
                    "専門用語が含まれる場合はわかりやすく説明してください。\n"
                    "不明確な情報しかない場合でも、誠実にその旨を伝えるようにしてください。"
                )},
                {"role": "user","content": prompt}
            ],
            temperature=0.2
        )
        ai_answer = r.choices[0].message.content
    except Exception as e:
        ai_answer = f"❌ OpenAI API 呼び出し失敗: {str(e)}"

    send_faq_with_feedback(say, "AI回答", ai_answer, "ai", corrected_query, user=user_id)

# ──────────────────────────────────────────────────────────────────────────────
# 14) Gmail 신규/범위 수집
# ──────────────────────────────────────────────────────────────────────────────
# ───── Gmail fetch concurrency guard ─────
ISF_LOCK = threading.Lock()
_is_fetching_map = {}

def _set_fetching(email: str, value: bool):
    with ISF_LOCK:
        _is_fetching_map[email] = value

def _is_fetching(email: str) -> bool:
    with ISF_LOCK:
        return _is_fetching_map.get(email, False)
    
def check_new_gmail_for_account(email, refresh_token):
    # fetch 진행 중 중복 방지
    if _is_fetching(email):
        print(f"🔁 {email}: 範囲取得中のため履歴チェックをスキップ")
        return

    access_token = refresh_gmail_token_for(refresh_token)
    if not access_token:
        print(f"[❌] Token refresh failed: {email}")
        return

    headers = {"Authorization": f"Bearer {access_token}"}
    profile_url = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
    res = http_get(profile_url, headers=headers)
    if res.status_code != 200:
        print(f"❌ Gmailプロファイル取得失敗: {res.status_code} / {res.text}")
        return

    latest_history_id = res.json().get("historyId")
    if not latest_history_id:
        print("❌ historyId取得失敗")
        return

    last_history_id = get_last_history_id(email)
    if not last_history_id:
        save_last_history_id(email, latest_history_id)
        print("📌 初回historyId保存")
        return

    history_url = "https://gmail.googleapis.com/gmail/v1/users/me/history"
    params = {
        "startHistoryId": last_history_id,
        "historyTypes": "messageAdded",
        "maxResults": 100
    }
    res = http_get(history_url, headers=headers, params=params)
    if res.status_code != 200:
        print(f"❌ Gmail履歴取得エラー: {res.text} -> latest_history_idでリセット")
        save_last_history_id(email, latest_history_id)
        return

    history = res.json().get("history", [])
    if not history:
        now = datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")
        print(f"📭 新着なし ({now})")
        save_last_history_id(email, latest_history_id)
        return

    # ✅ set으로 변경
    message_ids = set()
    for h in history:
        for m in h.get("messages", []):
            mid = m.get("id")
            if mid:
                message_ids.add(mid)

    if not message_ids:
        save_last_history_id(email, latest_history_id)
        return

    client = get_slack()
    channel = _channel_id("SLACK_CHANNEL_MAIL_ARCHIVE")
    if not channel:
        print("⚠️ SLACK_CHANNEL_MAIL_ARCHIVE 未設定。送信スキップ")
    else:
        # ✅ 정렬된 순회(선택)로 재현성 확보
        for msg_id in sorted(message_ids):
            detail_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}"
            msg_res = http_get(detail_url, headers=headers)
            if msg_res.status_code != 200:
                continue

            payload = msg_res.json()
            headers_data = payload.get("payload", {}).get("headers", [])
            subject = sender = "(不明)"
            for h in headers_data:
                if h["name"] == "Subject":
                    subject = h["value"]
                if h["name"] == "From":
                    sender = h["value"]

            body_text = extract_email_body(payload)
            short_body = body_text.strip().replace("\n", " ").replace("\r", "")[:500]

            try:
                safe_post_to_slack(
                    client,
                    channel=channel,
                    text=f"📧 *{subject}*\n👤 {sender}\n📜 {short_body}..."
                )
                time.sleep(1.8)
            except Exception as e:
                print(f"[⚠️ Slack 転送失敗] {e} / subject: {subject[:50]} / sender: {sender}")

    save_last_history_id(email, latest_history_id)
    print(f"✅ {len(message_ids)}件の新着メールをSlackに投稿しました")

# ───── Slack message chunking ─────
MAX_SLACK_LEN = 3600  # 헤더 포함 여유
def _send_mail_list_chunks(client, channel, email, items):
    header = f"📬 {email} のメール一覧:\n"
    buf = header
    for m in items:
        line = (
            f"• *{m['subject']}* 👤 {m['from']} 🕒 {m['date']}\n"
            f"   📝 {m['preview']}...\n"
        )
        if len(buf) + len(line) > MAX_SLACK_LEN:
            safe_post_to_slack(client, channel=channel, text=buf)
            time.sleep(1)
            buf = header
        buf += line
    if buf != header:
        safe_post_to_slack(client, channel=channel, text=buf)

def fetch_gmail_by_date_range(email, refresh_token, start_date, end_date, fetched_ids=None):
    access_token = refresh_gmail_token_for(refresh_token)
    if not access_token:
        return 0, (fetched_ids or set())
    if fetched_ids is None:
        fetched_ids = set()

    sd = datetime.strptime(start_date, "%Y-%m-%d").date()
    ed = datetime.strptime(end_date, "%Y-%m-%d").date()
    LABEL_FILTER = os.getenv("GMAIL_LABEL_FILTER", "").strip()

    query = (
        f"after:{sd.strftime('%Y/%m/%d')} "
        f"before:{(ed + timedelta(days=1)).strftime('%Y/%m/%d')} "
        "-in:spam -in:trash" + (f' label:"{LABEL_FILTER}"' if LABEL_FILTER else "")
    )
    url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"q": query, "maxResults": 100}

    total, new_ids, collected_mails = 0, set(), []
    while True:
        res = http_get(url, headers=headers, params=params)
        if res.status_code != 200:
            print(f"❌ メール検索失敗: {res.text}")
            break

        data = res.json()
        messages = data.get("messages", []) or []
        if not messages:
            break

        for msg in messages:
            msg_id = msg.get("id")
            if not msg_id or msg_id in fetched_ids:
                continue
            detail = http_get(f"{url}/{msg_id}", headers=headers)
            if detail.status_code != 200:
                continue

            payload = detail.json()
            headers_data = payload.get("payload", {}).get("headers", [])
            subject = sender = date_str = "(不明)"
            for h in headers_data:
                n = h.get("name")
                if n == "Subject": subject = h.get("value", "(不明)")
                elif n == "From": sender = h.get("value", "(不明)")
                elif n == "Date": date_str = h.get("value", "(不明)")

            preview = extract_email_body(payload).strip().replace("\n", " ").replace("\r", "")[:500]
            collected_mails.append({"subject": subject, "from": sender, "date": date_str, "preview": preview})
            total += 1
            new_ids.add(msg_id)

        next_token = data.get("nextPageToken")
        if not next_token:
            break
        params["pageToken"] = next_token

    # ← 루프 밖에서 한 번만 전송
    channel = _channel_id("SLACK_CHANNEL_MAIL_ARCHIVE")
    if channel and collected_mails:
        client = get_slack()
        for i in range(0, len(collected_mails), 50):
            _send_mail_list_chunks(client, channel, email, collected_mails[i:i+50])
            time.sleep(1)

    print(f"✅ {total}件のメール取得完了 ({start_date}〜{end_date})")
    fetched_ids |= new_ids
    return total, fetched_ids

def fetch_gmail_with_date_paging(email, refresh_token, start_date_str, end_date_str, step_days=3):
    _set_fetching(email, True)
    try:
        access_token = refresh_gmail_token_for(refresh_token)
        if not access_token:
            return 0
        headers = {"Authorization": f"Bearer {access_token}"}
        url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"

        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
        if start_date > end_date:
            print(f"[⚠️ 日付エラー] start_date({start_date}) > end_date({end_date})")
            return 0

        current_date, total_fetched = start_date, 0
        collected_chunk, CHUNK_SIZE = [], 50
        LABEL_FILTER = os.getenv("GMAIL_LABEL_FILTER", "").strip()

        def flush_chunk():
            nonlocal collected_chunk
            if not collected_chunk:
                return
            try:
                channel = _channel_id("SLACK_CHANNEL_MAIL_ARCHIVE")
                if channel:
                    _send_mail_list_chunks(get_slack(), channel, email, collected_chunk)
            except Exception as e:
                print(f"❌ Slack 転送失敗: {e}")
            finally:
                collected_chunk = []
                time.sleep(1.0)

        while current_date <= end_date:
            next_date = min(current_date + timedelta(days=step_days), end_date)
            query = (
                f"after:{current_date.strftime('%Y/%m/%d')} "
                f"before:{(next_date + timedelta(days=1)).strftime('%Y/%m/%d')} "
                "-in:spam -in:trash"
                + (f' label:"{LABEL_FILTER}"' if LABEL_FILTER else "")
            )

            slog("gmail.range", email=email, range=f"{current_date}~{next_date}", q=query)

            # ✅ 날짜 범위마다 params를 새로 초기화
            params = {"q": query, "maxResults": 100}

            print(f"🔎 Fetching {email}: {current_date} ~ {next_date}")
            print(f"🧪 Gmail クエリ: {query}")

            while True:
                try:
                    res = http_get(url, headers=headers, params=params)
                except Exception as e:
                    print(f"❌ メール照会通信失敗: {e}")
                    break

                if res.status_code != 200:
                    print(f"❌ メール照会失敗: status={res.status_code} body={res.text[:500]}")
                    break

                data = res.json()
                messages = data.get("messages", []) or []
                if not messages:
                    print(f"ℹ️ 範囲内メッセージ 0件: {current_date} ~ {next_date}")
                else:
                    for msg in messages:
                        msg_id = msg.get("id")
                        if not msg_id:
                            continue
                        detail = http_get(f"{url}/{msg_id}", headers=headers)
                        if detail.status_code != 200:
                            continue

                        payload = detail.json()
                        headers_data = payload.get("payload", {}).get("headers", [])
                        subject = sender = date_str = "(不明)"
                        for h in headers_data:
                            n = h.get("name")
                            if n == "Subject": subject = h.get("value", "(不明)")
                            elif n == "From": sender = h.get("value", "(不明)")
                            elif n == "Date": date_str = h.get("value", "(不明)")
                        preview = extract_email_body(payload).strip().replace("\n", " ").replace("\r", "")[:500]

                        collected_chunk.append({"subject": subject, "from": sender, "date": date_str, "preview": preview})
                        total_fetched += 1

                        if len(collected_chunk) >= CHUNK_SIZE:
                            flush_chunk()

                # ✅ 페이징 토큰은 날짜 루프 내부에서만 갱신
                next_token = data.get("nextPageToken")
                if not next_token:
                    break
                params["pageToken"] = next_token

            save_fetch_last_date(email, next_date.strftime("%Y-%m-%d"))
            current_date = next_date + timedelta(days=1)
            time.sleep(1.0)
            flush_chunk()

        # 루프 종료 후 profile 1회
        try:
            profile = http_get("https://gmail.googleapis.com/gmail/v1/users/me/profile", headers=headers)
            if profile.status_code == 200:
                hid = profile.json().get("historyId")
                if hid:
                    save_last_history_id(email, hid)
                    print(f"📗 history 更新: {email} -> {hid}")
            else:
                print(f"⚠️ profile取得失敗: status={profile.status_code} body={profile.text[:300]}")
        except Exception as e:
            print(f"⚠️ historyId 取得/保存 失敗: {e}")

        print(f"✅ 合計 {total_fetched}件のメールを処理しました ({start_date_str}〜{end_date_str})")
        return total_fetched
    finally:
        _set_fetching(email, False)

def archive_gmail_to_slack_channel(keyword):
    accounts = _load_gmail_accounts()

    if not accounts:
        return

    refresh_token = accounts[0]["refresh_token"]
    summary = search_gmail(keyword, refresh_token)
    try:
        channel = _channel_id("SLACK_CHANNEL_MAIL_ARCHIVE")
        if not channel:
            print("⚠️ SLACK_CHANNEL_MAIL_ARCHIVE 未設定。送信スキップ")
            # 필요시 return 또는送信部分のみスキップ
        if channel and summary:
            safe_post_to_slack(get_slack(), channel=channel, text=f"🔎 Gmail検索結果（{keyword}）\n{summary}")
    except Exception as e:
        print(f"[⚠️ Slack 転送失敗] {e}")

def _load_gmail_accounts():
    """Railway ではファイル配置が難しいため、環境変数 GMAIL_ACCOUNTS_JSON からも読み込む"""
    env_json = os.getenv("GMAIL_ACCOUNTS_JSON")
    if env_json:
        try:
            data = json.loads(env_json)
            accts = data.get("accounts", [])
            if isinstance(accts, dict):
                accts = [accts]
            return accts
        except Exception:
            return []
    try:
        with open("_load_gmail_accounts()") as f:
            return json.load(f).get("accounts", [])
    except Exception:
        return []

def _search_gmail_first_account(keyword: str) -> str:
    try:
        accounts = _load_gmail_accounts()
        if not accounts:
             return "📭 メールが見つかりませんでした。"
        refresh_token = accounts[0]["refresh_token"]
        return search_gmail(keyword, refresh_token)
    except Exception as e:
         return f"❌ Gmail検索エラー: {e}"

def _nohit(s: str) -> bool:
    s = (s or "").strip()
    return s.startswith(("🙅", "📭", "❌"))

# ──────────────────────────────────────────────────────────────────────────────
# 15) Flask – Gmail OAuth
# ──────────────────────────────────────────────────────────────────────────────
@flask_app.route("/gmail/auth")
def gmail_auth():
    import urllib.parse
    client_id = os.getenv("GMAIL_CLIENT_ID")
    redirect_uri = os.getenv("GMAIL_REDIRECT_URI")
    scope = "https://www.googleapis.com/auth/gmail.readonly"

    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "access_type": "offline",
        "prompt": "consent"
    })
    return redirect(auth_url)

@flask_app.route("/gmail/callback")
def gmail_callback():
    code = request.args.get("code")
    if not code:
        return "❌ 認証コードが見つかりません。", 400

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": os.getenv("GMAIL_CLIENT_ID"),
        "client_secret": os.getenv("GMAIL_CLIENT_SECRET"),
        "redirect_uri": os.getenv("GMAIL_REDIRECT_URI"),
        "grant_type": "authorization_code"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = http_post(token_url, data=data, headers=headers)
    if response.status_code != 200:
        return f"❌ トークン取得失敗: {response.text}", 400

    tokens = response.json()
    refresh_token = tokens.get("refresh_token")
    access_token = tokens.get("access_token")

    return f"""
    ✅ 認証成功！<br><br>
    <b>Access Token:</b> {access_token}<br>
    <b>Refresh Token:</b> {refresh_token}<br><br>
    <i>.env に保存してください。</i>
    """

# ──────────────────────────────────────────────────────────────────────────────
# 16) SocketMode 자동 재연결 루프
# ──────────────────────────────────────────────────────────────────────────────
def run_socketmode_with_reconnect(app, app_token):
    backoff = 1
    while True:
        handler = None
        try:
            handler = SocketModeHandler(app, app_token)
            handler.start()  # 블로킹
            backoff = 1
        except Exception as e:
            print(f"[SocketMode] クラッシュ: {e} → {backoff}s 後再起動")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
        finally:
            try:
                if handler and getattr(handler, "client", None):
                    handler.client.close()
            except Exception as e:
                print(f"[SocketMode] close失敗: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# 17) 메인 루틴
# ──────────────────────────────────────────────────────────────────────────────
def input_date_range():
    print("📅 過去メール収集用の日付範囲を指定してください（YYYY-MM-DD 形式）")
    start = input("▶ 開始日 (例: 2024-04-01): ").strip()
    end = input("▶ 終了日 (例: 2025-12-31): ").strip()
    return start, end

def start_auto_gmail_checker():
    def loop():
        while True:
            # Gmailアカウント設定の読み込み
            try:
                accounts = _load_gmail_accounts()
                if not isinstance(accounts, list):
                    print("❌ 'accounts' フィールドがリスト形式ではありません")
                    accounts = []
            except Exception as e:
                print(f"❌ _load_gmail_accounts() 読み込み失敗: {e}")
                accounts = []

            # 各アカウントの新着チェック
            for acct in accounts:
                try:
                    check_new_gmail_for_account(acct["email"], acct["refresh_token"])
                except Exception as e:
                    print(f"[❌ 自動チェック失敗] {acct.get('email','(unknown)')}: {e}")

            time.sleep(600)  # 10분
    # 必要に応じて自動チェックを有効化
    threading.Thread(target=loop, daemon=True).start()

if __name__ == "__main__":
    print("✅ chatbot.py 実行開始")
    try:
        _zendesk_env_guard()
        _zendesk_boot_healthcheck()
    except Exception as e:
        print(f"❌ Zendesk 初期化失敗: {e}")
        raise    

    # SocketMode 시작 (자동 재연결)
    try:
        print("🚀 Slack SocketModeHandler 起動中...")
        threading.Thread(
            target=run_socketmode_with_reconnect,
            args=(slack_app, os.getenv("SLACK_APP_TOKEN")),
            daemon=True
        ).start()
    except Exception as e:
        print(f"❌ Slack 初期化失敗: {e}")
        traceback.print_exc()

    # Gmail 메일 수집
    try:
        print("📬 Gmail メール取得開始")

        today = datetime.now(JST).date()
        default_start = today - timedelta(days=7)

        accounts = _load_gmail_accounts()
        if isinstance(accounts, dict):  # 단일 객체도 허용
            accounts = [accounts]
        if not accounts:
            print("⚠️ Gmailアカウント未設定。メール収集をスキップ")
            accounts = []

        for acct in accounts:
            email = acct["email"]
            refresh_token = acct["refresh_token"]
            check_new_gmail_for_account(email, refresh_token)

            last_date_str = get_fetch_last_date(email)
            if last_date_str:
                last_date = datetime.strptime(last_date_str, "%Y-%m-%d").date()
                start_date = min(last_date + timedelta(days=1), today)
            else:
                start_date = default_start

            end_date = today

            if start_date > end_date:
                print(f"⏭ {email}: 収集済み（start_date {start_date} > end_date {end_date}）")
                continue

            print(f"📩 {email}: {start_date} ～ {end_date} のメールを収集開始")

            try:
                fetch_gmail_with_date_paging(
                    email=email,
                    refresh_token=refresh_token,
                    start_date_str=start_date.strftime("%Y-%m-%d"),
                    end_date_str=end_date.strftime("%Y-%m-%d"),
                    step_days=3
                )
            except Exception as e:
                print(f"❌ {email} メール取得失敗: {e}")
                traceback.print_exc()

    except Exception as e:
        print(f"❌ Gmail メール取得ループ失敗: {e}")
        traceback.print_exc()

    start_auto_gmail_checker()

    # Flask 옵션 실행
    # Railway では HTTP リッスンが必要。PORT を使用して Flask を常時稼働
    if os.getenv("USE_FLASK", "false").lower() == "true":
        # ヘルスチェック/ルート
        @flask_app.get("/")
        def _root():
            return "ok", 200
        @flask_app.get("/healthz")
        def _healthz():
            return "ok", 200

        def run_flask():
            port = int(os.getenv("PORT", "5000"))  # ← Railway が付与する PORT を利用
            flask_app.run(host="0.0.0.0", port=port)
        threading.Thread(target=run_flask, daemon=True).start()
        print("🌐 Flaskサーバー起動 (/gmail/callback, /healthz 有効)")

    # 유지 루프
    try:
        print("🕒 実行継続中... Ctrl+C で終了")
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("🛑 手動で停止されました")