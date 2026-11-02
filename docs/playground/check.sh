#!/usr/bin/env bash
# playground の動作確認。server-a と server-b の間で、curl で mTLS の通信を確かめる。
#   - 許可した相手（server-a ⇔ server-b）は通る
#   - クライアント証明書の無い接続は拒否される
#   - 同じ CA の正しい証明書でも、許可していない相手（管理者の証明書）は拒否される
set -uo pipefail
cd "$(dirname "$0")"

DOMAIN=playground.internal
A=https://server-a.$DOMAIN:8443/hello
B=https://server-b.$DOMAIN:8443/hello
TLS=/etc/mtls-agent/tls
ADMIN_TLS=/etc/mtls-agent-admin/tls
pass=0 failed=0

# check 説明 期待（ok: 成功して本文に文字列を含む / code:NNN: HTTP の状態コード / reject: TLS で拒否） 文字列 サービス curl の引数...
check() {
  local title=$1 expect=$2 want=$3 svc=$4; shift 4
  local out rc code
  out=$(docker compose exec -T "$svc" curl -sS -w '\n%{http_code}' "$@" 2>&1); rc=$?
  code=$(printf '%s' "$out" | tail -n 1)
  out=$(printf '%s' "$out" | sed '$d')
  local ok=false
  case $expect in
    ok)     [ $rc -eq 0 ] && [ "$code" = 200 ] && printf '%s' "$out" | grep -qF "$want" && ok=true ;;
    code:*) [ "$code" = "${expect#code:}" ] && ok=true ;;
    reject) [ $rc -ne 0 ] && ok=true ;;
  esac
  if $ok; then
    pass=$((pass + 1)); printf '\033[32m[PASS]\033[0m %s\n' "$title"
  else
    failed=$((failed + 1)); printf '\033[31m[FAIL]\033[0m %s（期待: %s %s / 終了コード %s・HTTP %s）\n' "$title" "$expect" "$want" "$rc" "$code"
  fi
  printf '       %s\n' "$(printf '%s' "$out" | head -n 2 | tr '\n' ' ')"
}

mine="--cacert $TLS/ca.pem --cert $TLS/fullchain.pem --key $TLS/key.pem"
admin="--cacert $ADMIN_TLS/ca.pem --cert $ADMIN_TLS/fullchain.pem --key $ADMIN_TLS/key.pem"

echo "== 許可した相手どうしは通る"
# shellcheck disable=SC2086
check "server-a → server-b（nginx）" ok "hello from server-b" server-a $mine "$B"
# shellcheck disable=SC2086
check "server-b → server-a（Go）" ok "hello, [server-b.$DOMAIN]" server-b $mine "$A"

echo "== クライアント証明書が無いと拒否される"
check "証明書なし → server-b（nginx は 400）" code:400 "" server-a --cacert "$TLS/ca.pem" "$B"
check "証明書なし → server-a（TLS の握手で拒否）" reject "" server-b --cacert "$TLS/ca.pem" "$A"

echo "== 同じ CA の正しい証明書でも、許可していない相手は拒否される"
# shellcheck disable=SC2086
check "管理者の証明書 → server-b（nginx は 403）" code:403 "" mtls-manager $admin "$B"
# shellcheck disable=SC2086
check "管理者の証明書 → server-a（TLS の握手で拒否）" reject "" mtls-manager $admin "$A"

echo
if [ $failed -eq 0 ]; then
  printf '\033[32m%d 件すべて合格\033[0m\n' "$pass"
else
  printf '\033[31m%d 件中 %d 件が不合格\033[0m（docker compose logs で確かめる）\n' "$((pass + failed))" "$failed"
  exit 1
fi
