#!/bin/sh
# mtls-manager の起動。setup.sh が CA の設定を置くまで待ってから mtls-ca を起動する。
set -eu

CONFIG=/etc/mtls-ca/config.yaml

if [ ! -f "$CONFIG" ]; then
  echo "CA の設定がまだ無い。setup.sh を実行すると、ルート CA・中間 CA を作って mtls-ca を起動する"
  while [ ! -f "$CONFIG" ]; do sleep 1; done
fi

exec mtls-ca -config "$CONFIG"
