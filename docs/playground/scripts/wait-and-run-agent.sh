#!/bin/sh
# server-a / server-b の起動時に使う。setup.sh が mtls-agent の設定を置くまで待ち、mtls-agent を常駐させ、
# 最初の証明書ができるまで待つ（その後で、呼び出し元がアプリを起動する）。
set -eu

CONFIG=/etc/mtls-agent/config.yaml
CERT=/etc/mtls-agent/tls/fullchain.pem

if [ ! -f "$CONFIG" ]; then
  echo "mtls-agent の設定がまだ無い。setup.sh を実行すると、証明書を取得してアプリを起動する"
  while [ ! -f "$CONFIG" ]; do sleep 1; done
fi

echo "mtls-agent を起動する"
mtls-agent run -config "$CONFIG" &

while [ ! -s "$CERT" ]; do sleep 1; done
echo "証明書ができた。アプリを起動する"
