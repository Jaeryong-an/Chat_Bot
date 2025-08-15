# ベース: 軽量版Python
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# ビルド系(一部ライブラリで必要になるため最低限)
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 依存関係のインストール
COPY requirements.txt ./
RUN pip install -r requirements.txt

# アプリ本体
COPY . .

# Railway の正常性監視のため Flask を有効化
ENV USE_FLASK=true

# 実行。ファイル名は実際のスクリプト名に合わせて変更
CMD ["python", "-u", "chatbot_auto.py"]