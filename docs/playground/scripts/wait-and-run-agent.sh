#!/bin/sh
# server-a / server-b の起動時に使う。setup.sh が mtls-agent の設定を置くまで待ち、mtls-agent を常駐させ、
# 最初の証明書ができるまで待つ（その後で、呼び出し元がアプリを起動する）。
set -eu

# t 日本語 English: MTLS_LANG が en（en_US.UTF-8 なども可）なら英語を、それ以外は日本語を出す（プログラムと同じ決め方）。
t() { case "$(printf '%s' "${MTLS_LANG:-}" | tr 'A-Z' 'a-z')" in en | en[_.@-]*) printf '%s' "$2" ;; *) printf '%s' "$1" ;; esac; }

CONFIG=/etc/mtls-agent/config.yaml
CERT=/etc/mtls-agent/tls/fullchain.pem

if [ ! -f "$CONFIG" ]; then
  echo "$(t "mtls-agent の設定がまだ無い。setup.sh を実行すると、証明書を取得してアプリを起動する" "no mtls-agent configuration yet; run setup.sh to obtain a certificate and start the application")"
  while [ ! -f "$CONFIG" ]; do sleep 1; done
fi

echo "$(t "mtls-agent を起動する" "starting mtls-agent")"
mtls-agent run -config "$CONFIG" &

while [ ! -s "$CERT" ]; do sleep 1; done
echo "$(t "証明書ができた。アプリを起動する" "certificate ready; starting the application")"
