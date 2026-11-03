#!/usr/bin/env bash
# 管理者の証明書を取り直し、ブラウザに読み込むファイル（out/admin.p12 など）を書き出し直す。
# 管理者の証明書は、サーバの証明書と違って常駐の mtls-agent で更新しないので、24 時間で切れる。
# 切れて管理画面に入れなくなったら、これを実行して、新しい out/admin.p12 をブラウザに読み込み直す。
# （setup.sh も、初期設定の最後にこれを実行する）
set -euo pipefail
cd "$(dirname "$0")"

P12_PASS=playground
quiet=false
[ "${1:-}" = --quiet ] && quiet=true

m() { docker compose exec -T mtls-manager "$@"; }
fail() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }
# t 日本語 English: MTLS_LANG が en（en_US.UTF-8 なども可）なら英語を、それ以外は日本語を出す（プログラムと同じ決め方）。
t() { case "$(printf '%s' "${MTLS_LANG:-}" | tr 'A-Z' 'a-z')" in en | en[_.@-]*) printf '%s' "$2" ;; *) printf '%s' "$1" ;; esac; }

[ -n "$(docker compose ps -q --status running mtls-manager)" ] || fail "$(t "mtls-manager が動いていない。先に docker compose up -d を実行する" "mtls-manager is not running; run docker compose up -d first")"
m test -f /etc/mtls-agent-admin/config.yaml || fail "$(t "まだ初期設定をしていない。先に ./setup.sh を実行する" "not set up yet; run ./setup.sh first")"

# -force: 有効期限の前でも取り直す（切れた後も同じ）
m mtls-agent renew -force -config /etc/mtls-agent-admin/config.yaml
m openssl pkcs12 -export -in /etc/mtls-agent-admin/tls/fullchain.pem -inkey /etc/mtls-agent-admin/tls/key.pem \
  -name "mtls playground admin" -out /out/admin.p12 -passout "pass:$P12_PASS" \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
m cp /etc/mtls-ca/root.crt /out/root.crt
m cp /etc/mtls-agent-admin/tls/fullchain.pem /out/admin.crt
m cp /etc/mtls-agent-admin/tls/key.pem /out/admin.key
# 書き出したファイルを、PC の利用者が読めるようにする（Linux では bind mount の所有者がそのまま見える）
m chown "$(id -u):$(id -g)" /out/admin.p12 /out/root.crt /out/admin.crt /out/admin.key

$quiet && exit 0
expires=$(m openssl x509 -in /etc/mtls-agent-admin/tls/fullchain.pem -noout -enddate | cut -d= -f2)
if [ "$(t ja en)" = en ]; then
  cat <<EOF

$(printf '\033[32mRenewed the administrator certificate.\033[0m')
  Expires: $expires
  Remove the old administrator certificate (admin.admins.playground.internal) from your browser / OS
  and import the new out/admin.p12 (password: $P12_PASS) (see "4-2" in the README)
EOF
else
  cat <<EOF

$(printf '\033[32m管理者の証明書を取り直した。\033[0m')
  有効期限: $expires
  ブラウザ・OS から古い管理者の証明書（admin.admins.playground.internal）を消し、
  新しい out/admin.p12（パスワード: $P12_PASS）を読み込み直す（手順は README の「4-2」）
EOF
fi
