import gspread
from google.oauth2.service_account import Credentials
from collections import Counter
from datetime import datetime
import calendar

# === 設定 ===
SPREADSHEET_ID = "103F0opvu-DK-SoR4Gz_U6IIKYLwXDgfklet3TUZxYd4"
SHEET_NAME = "feedback"

# === 　認証 ===
credentials = Credentials.from_service_account_file(
    "gcp_service_account.json",
    scopes=["https://www.googleapis.com/auth/spreadsheets"]
)
gc = gspread.authorize(credentials)
ws = gc.open_by_key(SPREADSHEET_ID).worksheet(SHEET_NAME)

# === データ呼び込み ===
data = ws.get_all_values()
headers = data[0]
rows = data[1:]

# 列
idx_date = headers.index("timestamp")
idx_user = headers.index("user_id")
idx_faq = headers.index("faq_id")
idx_feedback = headers.index("feedback")
idx_comment = headers.index("comment")

# === 今月基準フィルター ===
now = datetime.now()
this_month = now.month
this_year = now.year

filtered = []
for row in rows:
    try:
        ts = datetime.fromisoformat(row[idx_date])
        if ts.year == this_year and ts.month == this_month:
            filtered.append(row)
    except:
        continue

# === 統計 計算 ===
total_yes = sum(1 for r in filtered if r[idx_feedback].strip().lower() == "yes")
total_no = sum(1 for r in filtered if r[idx_feedback].strip().lower() == "no")
no_with_comment = sum(1 for r in filtered if r[idx_feedback].strip().lower() == "no" and r[idx_comment].strip() != "")

faq_counter = Counter(r[idx_faq] for r in filtered)
top_faq = faq_counter.most_common(1)[0][0] if faq_counter else "なし"

# === 出力 ===
month_ja = f"{this_month}月"
print("📊 月間フィードバックレポート")
print(f"🗓️ 対象月: {month_ja}")
print(f"👍 ポジティブ: {total_yes} 件")
print(f"👎 ネガティブ: {total_no} 件（コメント付き: {no_with_comment} 件）")
print(f"🏆 フィードバック数トップFAQ: {top_faq}")
