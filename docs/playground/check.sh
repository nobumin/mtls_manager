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

# t 日本語 English: MTLS_LANG が en（en_US.UTF-8 なども可）なら英語を、それ以外は日本語を出す（プログラムと同じ決め方）。
t() { case "$(printf '%s' "${MTLS_LANG:-}" | tr 'A-Z' 'a-z')" in en | en[_.@-]*) printf '%s' "$2" ;; *) printf '%s' "$1" ;; esac; }

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
    # TLS で拒否されたときの curl の終了コードだけを合格にする。35: 握手の失敗、55・56: 握手の後に切られた
    # （TLS 1.3 では、サーバはクライアント証明書を握手の後で拒否するので、送信中・受信中に切られる）。
    # 名前が引けない（6）・つながらない（7）などは、拒否を確かめたことにならないので不合格。
    reject) case $rc in 35|55|56) ok=true ;; esac ;;
  esac
  if $ok; then
    pass=$((pass + 1)); printf '\033[32m[PASS]\033[0m %s\n' "$title"
  else
    failed=$((failed + 1)); printf "\033[31m[FAIL]\033[0m %s$(t "（期待: %s %s / 終了コード %s・HTTP %s）" " (expected: %s %s / exit code %s, HTTP %s)")\n" "$title" "$expect" "$want" "$rc" "$code"
  fi
  printf '       %s\n' "$(printf '%s' "$out" | head -n 2 | tr '\n' ' ')"
}

mine="--cacert $TLS/ca.pem --cert $TLS/fullchain.pem --key $TLS/key.pem"
admin="--cacert $ADMIN_TLS/ca.pem --cert $ADMIN_TLS/fullchain.pem --key $ADMIN_TLS/key.pem"

echo "== $(t "許可した相手どうしは通る" "Allowed peers can connect")"
# shellcheck disable=SC2086
check "$(t "server-a → server-b（nginx）" "server-a → server-b (nginx)")" ok "hello from server-b" server-a $mine "$B"
# shellcheck disable=SC2086
check "$(t "server-b → server-a（Go）" "server-b → server-a (Go)")" ok "hello, [server-b.$DOMAIN]" server-b $mine "$A"

echo "== $(t "クライアント証明書が無いと拒否される" "Connections without a client certificate are refused")"
check "$(t "証明書なし → server-b（nginx は 400）" "no certificate → server-b (nginx returns 400)")" code:400 "" server-a --cacert "$TLS/ca.pem" "$B"
check "$(t "証明書なし → server-a（TLS の握手で拒否）" "no certificate → server-a (refused in the TLS handshake)")" reject "" server-b --cacert "$TLS/ca.pem" "$A"

echo "== $(t "同じ CA の正しい証明書でも、許可していない相手は拒否される" "Peers that are not allowed are refused, even with a valid certificate from the same CA")"
# shellcheck disable=SC2086
check "$(t "管理者の証明書 → server-b（nginx は 403）" "administrator certificate → server-b (nginx returns 403)")" code:403 "" mtls-manager $admin "$B"
# shellcheck disable=SC2086
check "$(t "管理者の証明書 → server-a（TLS の握手で拒否）" "administrator certificate → server-a (refused in the TLS handshake)")" reject "" mtls-manager $admin "$A"

echo
if [ $failed -eq 0 ]; then
  printf "\033[32m$(t "%d 件すべて合格" "all %d passed")\033[0m\n" "$pass"
else
  printf "\033[31m$(t "%d 件中 %d 件が不合格" "%d checks, %d failed")\033[0m$(t "（docker compose logs で確かめる）" " (check with docker compose logs)")\n" "$((pass + failed))" "$failed"
  exit 1
fi
