#!/bin/sh
# mtls-manager の起動。setup.sh が CA の設定を置くまで待ってから mtls-ca を起動する。
set -eu

# t 日本語 English: MTLS_LANG が en（en_US.UTF-8 なども可）なら英語を、それ以外は日本語を出す（プログラムと同じ決め方）。
t() { case "$(printf '%s' "${MTLS_LANG:-}" | tr 'A-Z' 'a-z')" in en | en[_.@-]*) printf '%s' "$2" ;; *) printf '%s' "$1" ;; esac; }

CONFIG=/etc/mtls-ca/config.yaml

if [ ! -f "$CONFIG" ]; then
  echo "$(t "CA の設定がまだ無い。setup.sh を実行すると、ルート CA・中間 CA を作って mtls-ca を起動する" "no CA configuration yet; run setup.sh to create the root and intermediate CAs and start mtls-ca")"
  while [ ! -f "$CONFIG" ]; do sleep 1; done
fi

exec mtls-ca -config "$CONFIG"
