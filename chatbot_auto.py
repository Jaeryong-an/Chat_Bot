print("✅ chatbot_auto.py 実行開始")
import os, json, time, threading
import requests, base64
from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from flask import Flask, request
import gspread
from google.oauth2.service_account import Credentials
import datetime
import openai
from collections import OrderedDict
from openai import OpenAI

# ユーザーごとのフィードバックセッションを保持
user_feedback_sessions = {}
openai.api_key = os.getenv("OPENAI_API_KEY")

load_dotenv(dotenv_path=".env", override=True)

# =============================
# 👍 Google SpreadSheets
# =============================

def save_feedback_to_gsheet(faq_id, question, user_id, feedback, comment=""):
    try:
        SPREADSHEET_ID = os.getenv("GSHEET_ID")
        SHEET_NAME = os.getenv("GSHEET_SHEET", "feedback")
        credentials = Credentials.from_service_account_file(
            "gcp_service_account.json",
            scopes=["https://www.googleapis.com/auth/spreadsheets"]
        )
        gc = gspread.authorize(credentials)
        sh = gc.open_by_key(SPREADSHEET_ID)
        ws = sh.worksheet(SHEET_NAME)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ws.append_row([now, user_id, faq_id, question, feedback, comment])
        print(f"[✅ GSheet] {faq_id} - {feedback} saved")
    except Exception as e:
        print(f"[❌ GSheet ERROR] {str(e)}")

# =============================
# 🏣 Feedback button
# =============================

def safe_block_text(text, limit=2900):  # 3000以下推奨
    if len(text) > limit:
        return text[:limit] + "\n...(省略)"
    return text

def send_faq_with_feedback(say, title, answer, faq_id, corrected_query):
    context = f"ai::{corrected_query}"
    block_text = safe_block_text(f"📌 *{title}*\n📝 {answer}")
    
    blocks = [
        # 本文表示
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": block_text
            }
        },
        # 絵文字を含めたフィードバック案内
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*この回答は役に立ちましたか？*\n👍 はい　　👎 いいえ"
            }
        },
        # ボタンは絵文字なしで構成
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "はい"
                    },
                    "style": "primary",
                    "action_id": "faq_feedback_yes",
                    "value": context
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "いいえ"
                    },
                    "style": "danger",
                    "action_id": "faq_feedback_no",
                    "value": context
                }
            ]
        }
    ]
    
    say(
        text=f"FAQ: {title}",
        blocks=blocks
    )

# =============================
# 🔌 Slack アプリ初期化
# =============================
slack_app = App(token=os.getenv("SLACK_BOT_TOKEN"))
flask_app = Flask(__name__)

def get_channel_ids_from_env():
    """
    .envのSEARCH_CHANNELS_DBからチャンネルIDリスト取得（重複排除）
    """
    raw = os.getenv("SEARCH_CHANNELS_DB", "")
    return list(OrderedDict.fromkeys(raw.split(","))) if raw else []

def search_slack_channels(keyword):
    from slack_sdk import WebClient

    client = WebClient(token=os.getenv("SLACK_BOT_TOKEN"))
    channel_ids = get_channel_ids_from_env()
    results = []

    for channel_id in channel_ids:
        try:
            # 直近100件取得
            response = client.conversations_history(
                channel=channel_id,
                limit=100
            )
            messages = response.get("messages", [])
            for msg in messages:
                text = msg.get("text", "")
                if keyword.lower() in text.lower():
                    results.append(f"📌 <#{channel_id}>: {text.strip()[:100]}")
        except Exception as e:
            print(f"❌ Slack検索エラー ({channel_id}): {str(e)}")

    if not results:
        return "🙅 Slack内で関連するメッセージが見つかりませんでした。"
    return "\n".join(results[:10])


# =============================
# 🔁 Gmail アクセストークン更新
# =============================
def refresh_gmail_token_for(refresh_token):
    url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": os.getenv("GMAIL_CLIENT_ID"),
        "client_secret": os.getenv("GMAIL_CLIENT_SECRET"),
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    res = requests.post(url, data=data)
    if res.status_code == 200:
        return res.json()["access_token"]
    else:
        print("❌ Token refresh failed:", res.text)
        return None

# =============================
# 📥 Gmail キーワード検索
# =============================
def search_gmail(keyword, refresh_token, max_results=5):
    token = os.getenv("GMAIL_ACCESS_TOKEN")
    headers = {"Authorization": f"Bearer {token}"}
    params = {"q": keyword, "maxResults": max_results}
    url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"

    res = requests.get(url, headers=headers, params=params)
    if res.status_code == 401:
        token = refresh_gmail_token_for(refresh_token)
        if not token:
            return "❌ Gmailアクセストークンの更新に失敗しました。"
        headers["Authorization"] = f"Bearer {token}"
        res = requests.get(url, headers=headers, params=params)

    if res.status_code != 200:
        return f"❌ Gmail検索エラー: {res.text}"

    messages = res.json().get("messages", [])
    if not messages:
        return "📭 メールが見つかりませんでした。"

    results = []
    for msg in messages:
        msg_id = msg["id"]
        detail_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}"
        detail_res = requests.get(detail_url, headers=headers)
        if detail_res.status_code == 200:
            payload = detail_res.json()
            headers_data = payload.get("payload", {}).get("headers", [])
            subject = sender = "(不明)"
            for h in headers_data:
                if h["name"] == "Subject":
                    subject = h["value"]
                if h["name"] == "From":
                    sender = h["value"]
            results.append(f"📧 *{subject}*\n送信者: {sender}\n")
    return "\n".join(results)

# =============================
# 🧑 HubSpot 顧客検索
# =============================

# def get_hubspot_auth_url():
#     client_id = os.getenv("HUBSPOT_CLIENT_ID")
#     redirect_uri = os.getenv("HUBSPOT_REDIRECT_URI")
#     scopes = [
#         "crm.objects.companies.read",
#         "crm.objects.companies.write",
#         "crm.objects.contacts.read",
#         "crm.objects.contacts.write",
#         "crm.objects.deals.read",
#         "crm.objects.deals.write",
#         "crm.objects.products.read",
#         "crm.objects.products.write",
#         "oauth",
#         "tickets"
#     ]
#     scope_param = "%20".join(scopes)
#     url = (
#         "https://app.hubspot.com/oauth/authorize"
#         f"?client_id={client_id}"
#         f"&redirect_uri={redirect_uri}"
#         f"&scope={scope_param}"
#         f"&response_type=code"
#     )
#     return url

# # コンソールで試し
# if __name__ == "__main__":
#     print("HubSpot 인증 URL:")
#     print(get_hubspot_auth_url())


# @flask_app.route("/hubspot/callback")
# def hubspot_callback():
#     code = request.args.get("code")
#     if not code:
#         return "認証コードがありません", 400

#     url = "https://api.hubapi.com/oauth/v1/token"
#     data = {
#         "grant_type": "authorization_code",
#         "client_id": os.getenv("HUBSPOT_CLIENT_ID"),
#         "client_secret": os.getenv("HUBSPOT_CLIENT_SECRET"),
#         "redirect_uri": os.getenv("HUBSPOT_REDIRECT_URI"),
#         "code": code,
#     }
#     headers = {"Content-Type": "application/x-www-form-urlencoded"}
#     res = requests.post(url, data=data, headers=headers)
#     if res.status_code != 200:
#         return f"❌ 初回トークン取得失敗: {res.text}", 400
#     tokens = res.json()
#     # 최초 발급되는 refresh_token, access_token을 저장
#     refresh_token = tokens["refresh_token"]
#     access_token = tokens["access_token"]
#     return f"""
#     ✅ HubSpot認証成功!<br>
#     <b>Access Token:</b> {access_token}<br>
#     <b>Refresh Token:</b> {refresh_token}<br>
#     <i>.envまたは安全な場所に保存してください。</i>
#     """

# def refresh_hubspot_token():
#     url = "https://api.hubapi.com/oauth/v1/token"
#     data = {
#         "grant_type": "refresh_token",
#         "client_id": os.getenv("HUBSPOT_CLIENT_ID"),
#         "client_secret": os.getenv("HUBSPOT_CLIENT_SECRET"),
#         "refresh_token": os.getenv("HUBSPOT_REFRESH_TOKEN"),
#     }
#     headers = {
#         "Content-Type": "application/x-www-form-urlencoded"
#     }
#     res = requests.post(url, data=data, headers=headers)
#     if res.status_code == 200:
#         new_token = res.json()["access_token"]
#         os.environ["HUBSPOT_ACCESS_TOKEN"] = new_token
#         print("✅ HubSpotアクセストークン更新: ", new_token)
#         # (운영시 .env 저장까지 자동화 필요)
#         return new_token
#     else:
#         print("❌ HubSpot トークン自動更新失敗:", res.text)
#         return None


# def search_hubspot_contact(keyword):
#     token = os.getenv("HUBSPOT_ACCESS_TOKEN")
#     url = "https://api.hubapi.com/crm/v3/objects/contacts/search"
#     headers = {
#         "Authorization": f"Bearer {token}",
#         "Content-Type": "application/json"
#     }
#     data = {
#         "filterGroups": [{
#             "filters": [{
#                 "propertyName": "firstname",
#                 "operator": "CONTAINS_TOKEN",
#                 "value": keyword
#             }]
#         }],
#         "properties": ["firstname", "lastname", "email"],
#         "limit": 5
#     }
#     res = requests.post(url, headers=headers, json=data)
#     if res.status_code == 401:  # 만료 시 자동갱신
#         token = refresh_hubspot_token()
#         if not token:
#             return "❌ HubSpotアクセストークンの更新に失敗しました。"
#         headers["Authorization"] = f"Bearer {token}"
#         res = requests.post(url, headers=headers, json=data)
#     if res.status_code != 200:
#         return f"❌ HubSpot検索エラー: {res.text}"
#     results = res.json().get("results", [])
#     if not results:
#         return "🙅 顧客が見つかりませんでした。"
#     return "\n".join([
#         f"👤 {c['properties'].get('firstname', '')} {c['properties'].get('lastname', '')} - {c['properties'].get('email', '')}"
#         for c in results
#     ])

# =============================
# 📖 Notion FAQ検索
# =============================
from janome.tokenizer import Tokenizer
import re


def extract_keywords_jp(text):
    t = Tokenizer()
    keywords = []
    for token in t.tokenize(text):
        pos = token.part_of_speech.split(',')[0]
        if pos in ['名詞', '動詞', '形容詞']:
            keywords.append(token.base_form)
    return keywords

def search_notion_faq(keyword):
    input_words = set(extract_keywords_jp(keyword))
    notion_token = os.getenv("NOTION_API_TOKEN")
    database_ids = os.getenv("FAQ_DATABASE_ID", "").split(",")

    print(f"🔍 使用中のDatabase ID一覧: {database_ids}")

    headers = {
        "Authorization": f"Bearer {notion_token}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json"
    }

    all_results = []
    for db_id in database_ids:
        db_id = db_id.strip()
        if not db_id:
            continue  # 空いているIDは無視

        url = f"https://api.notion.com/v1/databases/{db_id}/query"
        res = requests.post(url, headers=headers, json={})
        if res.status_code == 200:
            results = res.json().get("results", [])
            all_results.extend(results)
        else:
            print(f"❌ Notion DB取得エラー ({db_id}): {res.status_code} - {res.text}")

    if not all_results:
        return "🙅 関連するFAQが見つかりませんでした。"

    scored = []
    for r in all_results:
        props = r.get("properties", {})
        title_data = props.get("Question", {}).get("title", [])
        qtext = title_data[0]["text"]["content"] if title_data else ""

        kwtext = " ".join(k["name"] for k in props.get("Keywords", {}).get("multi_select", []))

        alltext = f"{qtext} {kwtext}".strip()
        faq_words = set(extract_keywords_jp(alltext))
        score = len(input_words & faq_words)
        scored.append((score, r))

    scored = sorted(scored, key=lambda x: x[0], reverse=True)
    top_score = scored[0][0] if scored else 0
    best_faqs = [r for s, r in scored if s == top_score and s > 0]

    if not best_faqs:
        return "🙅 入力内容と類似するFAQが見つかりませんでした。"

    output = []
    for r in best_faqs:
        props = r.get("properties", {})
        title_data = props.get("Question", {}).get("title", [])
        title = title_data[0]["text"]["content"] if title_data else "（タイトルなし）"

        answer_blocks = props.get("Answer", {}).get("rich_text", [])
        answer = answer_blocks[0]["text"]["content"] if answer_blocks else "（回答なし）"

        sentences = re.split(r'[。\n]', answer)
        match_sents = [s for s in sentences if any(w in s for w in input_words) and s.strip()]
        match_text = " / ".join(match_sents) if match_sents else answer[:40] + "..."
        output.append(f"📌 *{title}*\n📝 {match_text}")

    return "\n\n".join(output)

# =============================
# 🎫 Zendesk チケット検索
# =============================
def search_zendesk_ticket_blocks(keyword):
    import os, requests

    subdomain = os.getenv("ZENDESK_SUBDOMAIN")
    email = os.getenv("ZENDESK_EMAIL")
    token = os.getenv("ZENDESK_API_TOKEN")
    query = f"type:ticket {keyword}"
    url = f"https://{subdomain}.zendesk.com/api/v2/search.json?query={query}"
    auth = (f"{email}/token", token)

    res = requests.get(url, auth=auth)
    if res.status_code != 200:
        return [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"❌ Zendesk検索エラー: {res.text}"}
        }]

    tickets = res.json().get("results", [])
    if not tickets:
        return [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": "🙅 チケットが見つかりませんでした。"}
        }]

    blocks = [{
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*🎫 Zendesk チケット検索結果:*"}
    }]

    for t in tickets[:5]:
        ticket_id = t.get("id", "")
        subject = t.get("subject", "(件名不明)")
        status = t.get("status", "(ステータス不明)")
        url = f"https://{subdomain}.zendesk.com/agent/tickets/{ticket_id}"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*<{url}|#{ticket_id} - {subject}>*\nステータス: `{status}`"
            }
        })
        blocks.append({"type": "divider"})

    return blocks

# =============================
# 🧠 メッセージから用途（意図）を判定
# =============================
def detect_intent(text):
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["gmail", "メール", "mail", "メール検索"]):
        return "メール"
    # if any(kw in text_lower for kw in ["hubspot", "顧客", "contact", "リード"]):
    #     return "顧客"
    if any(kw in text_lower for kw in ["notion", "faq", "方法", "やり方", "使い方", "できない", "how", "help"]):
        return "FAQ"
    if any(kw in text_lower for kw in ["zendesk", "チケット", "ゼンデスク"]):
        return "チケット"
    return None

# =============================
# 🧾 キーワード部分のみ抽出
# =============================
def extract_keyword(text, intent):
    import re
    if intent == "メール":
        text = re.sub(r"(gmail|メール|mail|メール検索)", "", text, flags=re.I)
    elif intent == "顧客":
    #     text = re.sub(r"(hubspot|顧客|contact|リード)", "", text, flags=re.I)
    # elif intent == "FAQ":
        text = re.sub(r"(notion|faq|方法|やり方|使い方|できない|how|help)", "", text, flags=re.I)
    elif intent == "チケット":
        text = re.sub(r"(zendesk|チケット|ゼンデスク)", "", text, flags=re.I)
    return text.strip()

# =============================
# 🔘 Feedback
# =============================
@slack_app.action("faq_feedback_yes")
def handle_feedback_yes(ack, body, say):
    ack()
    user = body["user"]["id"]
    value = body["actions"][0]["value"]
    try:
        faq_id, question = value.split("::", 1)
    except ValueError:
        faq_id, question = value, ""
    print(f"[📥 Feedback YES] {faq_id=} {question=}")
    save_feedback_to_gsheet(faq_id, question, user, "yes")
    say("👍 フィードバックありがとうございます！")


@slack_app.action("faq_feedback_no")
def handle_feedback_no(ack, body, say, client):
    ack()
    user = body["user"]["id"]
    value = body["actions"][0]["value"]
    try:
        faq_id, question = value.split("::", 1)
    except ValueError:
        faq_id, question = value, ""

    # ✅ セッション上書き前に古いセッション削除（安全のため）
    user_feedback_sessions.pop(user, None)

    # ✅ 新しいセッション記録
    user_feedback_sessions[user] = {
        "faq_id": faq_id,
        "question": question,
        "timestamp": time.time()
    }

    say("ご不明点についてご記入ください。")

def correct_typo_with_gpt(input_text: str) -> str:
    try:
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "あなたは日本語のスペルチェッカーです。\n"
                        "与えられた日本語の文に対して、誤字・脱字・タイプミスのみを修正してください。\n"
                        "文の意味や言い回しは一切変更せず、文脈を維持したまま自然な日本語にしてください。\n"
                        "修正が不要な場合は、入力をそのまま返してください。"
                    )
                },
                {
                    "role": "user",
                    "content": input_text 
                }
            ],
            temperature=0
        )

        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[❌ 誤字修正失敗] {str(e)}")
        return input_text

def reminder_or_autosave(user_id, faq_id, question, client):
    time.sleep(600)
    session = user_feedback_sessions.get(user_id)

    if session and session.get("faq_id") == faq_id:
        try:
            save_feedback_to_gsheet(faq_id, question, user_id, "no", comment="コメントなし")
        except Exception as e:
            print(f"❌ Google Sheets 保存失敗: {e}")

        try:
            client.chat_postMessage(
                channel="feedback-momentum",
                text=(
                    f"📝 フィードバック（自動保存）\n"
                    f"*質問:* {question}\n"
                    f"*ユーザー:* <@{user_id}>\n"
                    f"*コメント:* コメントなし"
                )
            )
        except Exception as e:
            print(f"❌ Slack 通知失敗: {e}")

        user_feedback_sessions.pop(user_id, None)

def start_feedback_timer(user_id, faq_id, question, client):
    threading.Thread(
        target=reminder_or_autosave,
        args=(user_id, faq_id, question, client),
        daemon=True
    ).start()

# =============================
# 📣 Slackメンションイベント処理
# =============================
@slack_app.event("app_mention")
def handle_mention_events(body, say):
    text = body.get("event", {}).get("text", "")
    bot_user_id = body["authorizations"][0]["user_id"]
    user_id = body["event"]["user"]
    clean_text = text.replace(f"<@{bot_user_id}>", "").strip()
    user_query = clean_text

    # ✅ 誤字修正ステップ（GPT）
    corrected_query = correct_typo_with_gpt(user_query)
    print(f"[ユーザー入力] {user_query} → [修正後] {corrected_query}")

    # 🔎 検索中メッセージ
    say(text="🔎 検索中です。少々お待ちください...")

    # ✅ Notion / Zendesk / Slack 検索（すべて corrected_query を使用）
    faq_result = search_notion_faq(corrected_query)
    zendesk_result = search_zendesk_ticket_blocks(corrected_query)
    slack_result = search_slack_channels(corrected_query)

    # ✅ Gmailアーカイブスレッド実行（非同期）
    threading.Thread(target=archive_gmail_to_slack_channel, args=(corrected_query,)).start()

    # ✅ 回答生成用プロンプト
    prompt = (
        f"ユーザーからの質問: {corrected_query}\n\n"
        f"以下は、ユーザーの質問に関連する検索結果です。\n\n"
        f"■ FAQ 検索結果:\n{faq_result}\n\n"
        f"■ Zendesk チケット検索結果:\n{zendesk_result}\n\n"
        f"■ Slack チャネル検索結果:\n{slack_result}\n\n"
        "上記の情報をもとにして、ユーザーの質問に対して最も関連性が高い内容を選び、"
        "丁寧で明確な日本語で2〜3文以内に簡潔に回答してください。\n"
        "もし情報が不十分な場合は、その旨を丁寧に伝えてください。\n"
        "回答は日本語で自然な口調で、専門用語はできるだけわかりやすく説明してください。"
    )

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "あなたはSlack上で動作するアシスタントボットです。\n"
                        "ユーザーの質問に対して、以下の複数の情報源（FAQ、Zendesk、Slack過去投稿）を参照し、"
                        "最も信頼性が高く、関連性のある回答を日本語で作成してください。\n"
                        "回答は2〜3文程度の丁寧で簡潔な表現とし、"
                        "専門用語が含まれる場合はわかりやすく説明してください。\n"
                        "不明確な情報しかない場合でも、誠実にその旨を伝えるようにしてください。"
                    )
                },
                {
                    "role": "user",
                    "content": prompt  # 위에서 구성한 corrected_query 기반 prompt
                }
            ],
            temperature=0.3
        )
        ai_answer = response.choices[0].message.content
    except Exception as e:
        ai_answer = f"❌ OpenAI API 呼び出し失敗: {str(e)}"

    # ✅ コンテキスト値をJSON文字列として保存（FAQ IDと質問）
    context = f"ai::{corrected_query}"

    say(
        text=f"🤖 <@{user_id}> さんへの回答です",
        blocks=[
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*🤖 回答 (<@{user_id}>):*\n{ai_answer}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "*この回答は役に立ちましたか？*"}},
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "はい", "emoji": True}, "style": "primary", "action_id": "faq_feedback_yes", "value": context},
                {"type": "button", "text": {"type": "plain_text", "text": "いいえ", "emoji": True}, "style": "danger", "action_id": "faq_feedback_no", "value": context}
            ]}
        ]
    )

    # ✅ フィードバックセッション記録
    user_feedback_sessions[user_id] = {
        "faq_id": "ai",
        "question": corrected_query,
        "answered_time": time.time()
    }

    # ✅ 10分後自動保存スレッド起動
    threading.Thread(
        target=reminder_or_autosave,
        args=(user_id, "ai", corrected_query, slack_app.client),
        daemon=True
    ).start()

def archive_gmail_to_slack_channel(keyword):
    import os, json
    from slack_sdk import WebClient

    try:
        with open("gmail_accounts.json") as f:
            accounts = json.load(f).get("accounts", [])
    except Exception as e:
        print(f"❌ gmail_accounts.json 読み込み失敗: {e}")
        accounts = []

    if not accounts:
        return

    refresh_token = accounts[0]["refresh_token"]
    search_gmail(keyword, refresh_token)  # Slack 転送のみ遂行


@slack_app.event("message")
def handle_additional_comment(body, say, client):
    event = body.get("event", {})
    user = event.get("user")
    text = event.get("text")
    subtype = event.get("subtype")

    # Botのメッセージもしくは内容がないメッセージは無視
    if subtype == "bot_message" or user is None or not text:
        return

    # ユーザーのフィードバックがある場合の処理
    if user in user_feedback_sessions:
        session = user_feedback_sessions.pop(user)
        faq_id = session["faq_id"]
        question = session["question"]

        # ✅ ① Google Sheets に保存
        save_feedback_to_gsheet(faq_id, question, user, "no", comment=text)

        # ✅ ② Slack チャンネル (#feedback-momentum) に通知
        client.chat_postMessage(
            channel="feedback-momentum",  
            text=(
                f"📝 フィードバックコメント受信\n"
                f"*質問:* {question}\n"
                f"*ユーザー:* <@{user}>\n"
                f"*コメント:*\n{text}"
            )
        )

        # ✅ ③ ユーザーへ返信
        say("コメントありがとうございます。内容をチームに共有しました。")


# =============================
# 🚪 Gmail 認証コールバック (Flask)
# =============================
from slack_sdk import WebClient
import schedule

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

    response = requests.post(token_url, data=data, headers=headers)
    if response.status_code != 200:
        return f"❌ トークン取得失敗: {response.text}", 400

    tokens = response.json()
    refresh_token = tokens.get("refresh_token")
    access_token = tokens.get("access_token")
    import json
    with open("gmail_accounts.json") as f:
        accounts = json.load(f)["accounts"]

    return f"""
    ✅ 認証成功！<br><br>
    <b>Access Token:</b> {access_token}<br>
    <b>Refresh Token:</b> {refresh_token}<br><br>
    <i>.env に保存してください。</i>
    """

def get_last_history_id(email):
    import gspread
    from google.oauth2.service_account import Credentials
    import os, json

    credentials = Credentials.from_service_account_info(
        json.loads(os.getenv("GCP_SERVICE_ACCOUNT_JSON")),
        scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )
    client = gspread.authorize(credentials)
    sheet = client.open_by_key(os.getenv("GSHEET_ID")).worksheet("history")

    try:
        cell = sheet.find(email)
        return sheet.cell(cell.row, cell.col + 1).value  # B열 = history_id
    except gspread.exceptions.CellNotFound:
        return None


def save_last_history_id(email, history_id):
    import gspread
    from google.oauth2.service_account import Credentials
    import os, json

    credentials = Credentials.from_service_account_info(
        json.loads(os.getenv("GCP_SERVICE_ACCOUNT_JSON")),
        scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )
    client = gspread.authorize(credentials)
    sheet = client.open_by_key(os.getenv("GSHEET_ID")).worksheet("history")

    try:
        cell = sheet.find(email)
        prev_id = sheet.cell(cell.row, cell.col + 1).value
        sheet.update_cell(cell.row, cell.col + 1, str(history_id))
    except gspread.exceptions.CellNotFound:
        prev_id = None
        sheet.append_row([email, str(history_id)])

    if prev_id != str(history_id):
        print(f"📗 [HISTORY ID] {email} 更新: {history_id}")
        send_log_to_slack(f"📗 *HISTORY_ID更新: {email}*\n・新しいID: `{history_id}`")
    
def send_log_to_slack(text, channel=None, title="📘 LOG通知", color="#439FE0"):
    try:
        slack = WebClient(token=os.getenv("SLACK_BOT_TOKEN"))
        if not channel:
            channel = os.getenv("SLACK_CHANNEL_LOG", "#log")

        slack.chat_postMessage(
            channel=channel,
            blocks=[
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": title
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": text
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"`{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}` に送信されました"
                        }
                    ]
                }
            ]
        )
    except Exception as e:
        print(f"[⚠️ Slackログ送信失敗] {e}")


def extract_email_body(payload):

    def decode_base64(data):
        try:
            return base64.urlsafe_b64decode(data).decode("utf-8")
        except:
            try:
                return base64.urlsafe_b64decode(data).decode("ISO-2022-JP")
            except:
                return "(本文デコード失敗)"

    def find_text_part(parts):
        for part in parts:
            mime_type = part.get("mimeType", "")
            body_data = part.get("body", {}).get("data", "")
            if mime_type == "text/plain" and body_data:
                return decode_base64(body_data)
            # nested parts
            if "parts" in part:
                nested = find_text_part(part["parts"])
                if nested:
                    return nested
        return None

    payload_main = payload.get("payload", {})
    parts = payload_main.get("parts", [])
    
    # ✅ text/plain
    if parts:
        text = find_text_part(parts)
        if text:
            return text

    # ✅ マルチパートがない場合の本文
    body_data = payload_main.get("body", {}).get("data", "")
    if body_data:
        return decode_base64(body_data)

    # ✅ fallback: text/html
    for part in parts:
        if part.get("mimeType") == "text/html":
            body_data = part.get("body", {}).get("data", "")
            return decode_base64(body_data)

    return "(本文なし)"


def check_new_gmail_for_account(email, refresh_token):
    access_token = refresh_gmail_token_for(refresh_token)
    if not access_token:
        print(f"[❌] Token refresh failed: {email}")
        return

    headers = {"Authorization": f"Bearer {access_token}"}
    profile_url = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
    res = requests.get(profile_url, headers=headers)
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
        "maxResults": 10
    }
    res = requests.get(history_url, headers=headers, params=params)
    if res.status_code != 200:
        print(f"❌ Gmail履歴取得エラー: {res.text}")
        return

    history = res.json().get("history", [])
    if not history:
        print("📭 新着なし")
        save_last_history_id(email, latest_history_id)
        return

    message_ids = []
    for h in history:
        for m in h.get("messages", []):
            message_ids.append(m["id"])

    if not message_ids:
        save_last_history_id(email, latest_history_id)
        return

    slack = WebClient(token=os.getenv("SLACK_BOT_TOKEN"))
    channel = os.getenv("SLACK_CHANNEL_MAIL_ARCHIVE")

    for msg_id in message_ids:
        detail_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}"
        msg_res = requests.get(detail_url, headers=headers)
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
            slack.chat_postMessage(
                channel=channel,
                text=f"📧 *{subject}*\n👤 {sender}\n📝 {short_body}..."
            )
            time.sleep(1.8)
        except Exception as e:
            print(f"[⚠️ Slack 転送失敗] {e} / subject: {subject[:50]} / sender: {sender}")

    # ✅ 全てのメッセージ処理後historyId保存
    save_last_history_id(email, latest_history_id)
    print(f"✅ {len(message_ids)}件の新着メールをSlackに投稿しました")

def fetch_gmail_by_date_range(email, refresh_token, start_date, end_date, fetched_ids=None):
    print(f"📬 {email} のメールを {start_date}〜{end_date} の範囲で取得中...")
    access_token = refresh_gmail_token_for(refresh_token)
    if not access_token:
        return 0, set()

    if fetched_ids is None:
        fetched_ids = set()

    query = f"after:{start_date.replace('-', '/')} before:{end_date.replace('-', '/')} -in:spam -in:trash"
    url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"q": query, "maxResults": 100}

    slack = WebClient(token=os.getenv("SLACK_BOT_TOKEN"))
    channel = os.getenv("SLACK_CHANNEL_MAIL_ARCHIVE")
    total = 0
    new_ids = set()
    collected_mails = []  # ✅ Slack転送ようメール情報リスト

    while True:
        res = requests.get(url, headers=headers, params=params)
        if res.status_code != 200:
            print(f"❌ メール検索失敗: {res.text}")
            break

        data = res.json()
        messages = data.get("messages", [])
        if not messages:
            break

        for msg in messages:
            msg_id = msg["id"]
            if msg_id in fetched_ids:
                continue

            detail_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}"
            msg_res = requests.get(detail_url, headers=headers)
            if msg_res.status_code != 200:
                continue

            payload = msg_res.json()
            headers_data = payload.get("payload", {}).get("headers", [])
            subject = sender = date_str = "(不明)"
            for h in headers_data:
                if h["name"] == "Subject":
                    subject = h["value"]
                if h["name"] == "From":
                    sender = h["value"]
                if h["name"] == "Date":
                    date_str = h["value"]

            body_text = extract_email_body(payload)
            short_body = body_text.strip().replace("\n", " ").replace("\r", "")[:500]

            collected_mails.append({  # ✅ リストへ保存
                "subject": subject,
                "from": sender,
                "date": date_str,
                "preview": short_body
            })

            total += 1
            new_ids.add(msg_id)

        next_token = data.get("nextPageToken")
        if not next_token:
            break
        params["pageToken"] = next_token

    # ✅ 50件ずつまとめてSlackへ転送
    chunk_size = 50
    for i in range(0, len(collected_mails), chunk_size):
        chunk = collected_mails[i:i+chunk_size]
        
        message_blocks = []
        for m in chunk:
            message_blocks.append(
                f"• *{m['subject']}* 👤 {m['from']} 🕒 {m['date']}\n   📝 {m['preview']}..."
            )

        try:
            slack.chat_postMessage(
                channel=channel,
                text=f"📬 {email} のメール一覧:\n" + "\n".join(message_blocks)
            )
            time.sleep(1)  # Slack rate limit 回避
        except Exception as e:
            print(f"❌ Slack 転送失敗: {e}")

    print(f"✅ {total}件のメール取得完了 ({start_date}〜{end_date})")
    return total, new_ids

def load_fetch_log():
    try:
        with open(".gmail_fetch_log.json", "r") as f:
            return json.load(f)
    except:
        return {}

def save_fetch_log(log_data):
    with open(".gmail_fetch_log.json", "r") as f:
        prev_log = json.load(f) if os.path.exists(".gmail_fetch_log.json") else {}

    with open(".gmail_fetch_log.json", "w") as f:
        json.dump(log_data, f, indent=2)

    # 변경 사항 보고
    for email, info in log_data.items():
        prev_info = prev_log.get(email, {})
        if prev_info != info:
            print(f"📘 [FETCH LOG] {email} 更新:\n - last_date: {info.get('last_date')}")
            send_log_to_slack(f"📘 *FETCH_LOG更新: {email}*\n・最終日付: `{info.get('last_date')}`\n・件数: {len(info.get('fetched_ids', []))}")

def fetch_gmail_with_date_paging(email, refresh_token, start_date_str, end_date_str, step_days=3, fetch_log=None):
    from datetime import datetime, timedelta

    access_token = refresh_gmail_token_for(refresh_token)
    if not access_token:
        print(f"[❌] Token refresh failed for: {email}")
        return 0

    headers = {"Authorization": f"Bearer {access_token}"}

    # 🔄 fetch_logを外部から読み取り
    if fetch_log is None:
        fetch_log = load_fetch_log()

    fetched_ids = set()
    log_entry = fetch_log.get(email, {})
    if isinstance(log_entry, dict):
        fetched_ids = set(log_entry.get("fetched_ids", []))

    start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
    end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
    current_date = start_date

    total_fetched = 0

    while current_date <= end_date:
        next_date = current_date + timedelta(days=step_days)
        if next_date > end_date:
            next_date = end_date

        query = (
            f"after:{current_date.strftime('%Y/%m/%d')} "
            f"before:{(next_date + timedelta(days=1)).strftime('%Y/%m/%d')} "
            f"label:inbox"
        )
        url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages"
        params = {
            "q": query,
            "maxResults": 100
        }
        res = requests.get(url, headers=headers, params=params)

        if res.status_code != 200:
            print(f"❌ メール取得エラー: {res.status_code} {res.text}")
            break

        messages = res.json().get("messages", [])
        new_ids = [msg["id"] for msg in messages if msg["id"] not in fetched_ids]
        total_fetched += len(new_ids)

        print(f"✅ {len(new_ids)}件のメール取得完了 ({current_date}〜{next_date})")

        fetched_ids.update(new_ids)

        # ✅ 集めた範囲保存
        fetch_log[email] = {
            "last_date": next_date.strftime("%Y-%m-%d"),
            "fetched_ids": list(fetched_ids)
        }
        save_fetch_log(fetch_log)

        current_date = next_date + timedelta(days=1)
        time.sleep(1.5)

    return total_fetched

def input_date_range():
    print("📅 過去メール収集用の日付範囲を指定してください（YYYY-MM-DD 形式）")
    start = input("▶ 開始日 (例: 2024-04-01): ").strip()
    end = input("▶ 終了日 (例: 2025-12-31): ").strip()
    return start, end

def start_auto_gmail_checker():
    def loop():
        while True:
            try:
                with open("gmail_accounts.json") as f:
                    config = json.load(f)
                    accounts = config.get("accounts", [])
                    if not isinstance(accounts, list):
                        print("❌ 'accounts' フィールドがリスト形式ではありません")
                        accounts = []
            except Exception as e:
                print(f"❌ gmail_accounts.json 読み込み失敗: {e}")
                accounts = []

            for acct in config.get("accounts", []):
                try:
                    check_new_gmail_for_account(acct["email"], acct["refresh_token"])
                except Exception as e:
                    print(f"[❌ 自動チェック失敗] {acct['email']}: {e}")

            time.sleep(3600)  # 1時間ごとにチェック

    threading.Thread(target=loop, daemon=True).start()

if __name__ == "__main__":
    import threading
    from datetime import datetime, timedelta
    import traceback

    print("🚀 chatbot_auto.py 起動開始")

    # ✅ オンタイム感知開始
    try:
        print("🟢 start_auto_gmail_checker 実行")
        start_auto_gmail_checker()
    except Exception as e:
        print(f"❌ start_auto_gmail_checker 失敗: {e}")
        traceback.print_exc()

    # ✅ Slack 実行
    try:
        print("🟢 Slack SocketModeHandler 起動")
        handler = SocketModeHandler(slack_app, os.getenv("SLACK_APP_TOKEN"))
        threading.Thread(target=handler.start, daemon=True).start()
    except Exception as e:
        print(f"❌ Slack 起動失敗: {e}")
        traceback.print_exc()

    # ✅ Gmail アカウント読み込みと収集開始
    today = datetime.today().date()
    default_start = today - timedelta(days=7)

    try:
        print("📄 gmail_accounts.json 読み込み中...")
        with open("gmail_accounts.json") as f:
            config = json.load(f)
            accounts = config.get("accounts", [])
            if not isinstance(accounts, list):
                print("❌ 'accounts' フィールド形式エラー")
                accounts = []
    except Exception as e:
        print(f"❌ gmail_accounts.json 読み込み失敗: {e}")
        accounts = []

    fetch_log = load_fetch_log()

    for acct in accounts:
        email = acct["email"]
        refresh_token = acct["refresh_token"]

        log_entry = fetch_log.get(email)
        if isinstance(log_entry, dict) and log_entry.get("last_date"):
            start_date = datetime.strptime(log_entry["last_date"], "%Y-%m-%d").date() + timedelta(days=1)
        else:
            start_date = default_start

        end_date = today

        print(f"📩 {email}: {start_date} ～ {end_date} のメールを収集開始")

        try:
            fetch_gmail_with_date_paging(
                email=email,
                refresh_token=refresh_token,
                start_date_str=start_date.strftime("%Y-%m-%d"),
                end_date_str=end_date.strftime("%Y-%m-%d"),
                step_days=3,
                fetch_log=fetch_log
            )
        except Exception as e:
            print(f"❌ {email} のGmail取得エラー: {e}")
            traceback.print_exc()

    # ✅ Flask サーバー起動（必要に応じて）
    if os.getenv("USE_FLASK", "false").lower() == "true":
        try:
            def run_flask():
                print("🚀 Flaskサーバー起動...")
                flask_app.run(host="0.0.0.0", port=5000)

            threading.Thread(target=run_flask, daemon=True).start()
        except Exception as e:
            print(f"❌ Flask 起動失敗: {e}")
            traceback.print_exc()

    # ✅ プログラム継続用スリープ
    print("🕒 バックグラウンドで実行中。Slack と Gmail 感知維持中...")
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("🛑 手動終了されました。")

