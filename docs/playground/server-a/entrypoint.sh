#!/bin/sh
# server-a: Go のアプリ（examples/go/server。mtls ライブラリを使う）。
# 接続を許可する相手は server-b だけ。証明書は mtls-agent が更新し、アプリは再起動なしで新しい証明書を使う。
set -eu

/usr/local/bin/wait-and-run-agent.sh

exec server-a -addr :8443 \
  -cert /etc/mtls-agent/tls/fullchain.pem -key /etc/mtls-agent/tls/key.pem -ca /etc/mtls-agent/tls/ca.pem \
  -allow server-b.playground.internal
