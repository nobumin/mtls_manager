#!/usr/bin/env bash
# playground の初期設定。`docker compose up -d --build` の後に 1 回だけ実行する。
#   1. mtls-manager: ルート CA・中間 CA を作り、EAB 鍵を発行し、CA（管理画面つき）を起動する
#   2. server-a / server-b: mtls-agent の設定を置く → 各コンテナが証明書を取得してアプリを起動する
#   3. 管理者の証明書を取得し、ブラウザに読み込むファイル（out/admin.p12）とルート CA（out/root.crt）を書き出す
# 体験用の手順なので、本番ではオフラインの端末に置くべきルート CA の鍵も、mtls-manager のコンテナの中で作る。
set -euo pipefail
cd "$(dirname "$0")"

DOMAIN=playground.internal
CA_HOST=ca.$DOMAIN
ADMIN=admin.admins.$DOMAIN
P12_PASS=playground

m() { dc exec -T mtls-manager "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# t 日本語 English: MTLS_LANG が en（en_US.UTF-8 なども可）なら英語を、それ以外は日本語を出す（プログラムと同じ決め方）。
t() { case "$(printf '%s' "${MTLS_LANG:-}" | tr 'A-Z' 'a-z')" in en | en[_.@-]*) printf '%s' "$2" ;; *) printf '%s' "$1" ;; esac; }

# docker compose を使う。Compose のプラグイン（docker compose）が無ければ、単体の docker-compose（v2 以降）を使う
# （Homebrew などで docker-compose だけを入れた macOS では、docker compose が使えない）。
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif docker-compose version --short 2>/dev/null | grep -Eq '^v?([2-9]|[1-9][0-9])\.'; then
  DC=docker-compose
else
  fail "$(t "Docker Compose（v2 以降）が見つからない。docker compose version で確かめる（README の「うまくいかないとき」を参照）" "Docker Compose (v2 or later) not found; check with docker compose version (see Troubleshooting in the README)")"
fi
# shellcheck disable=SC2086 # DC は "docker compose" のように 2 語になるので、分けて渡す
dc() { $DC "$@"; }

# put SERVICE PATH MODE: 標準入力の内容を、コンテナの中のファイルに書く
put() { dc exec -T "$1" sh -c "umask 077; cat > '$2' && chmod $3 '$2'"; }

# wait_for 説明 秒数 コマンド...: コマンドが成功するまで待つ
wait_for() {
  local what=$1 secs=$2; shift 2
  for _ in $(seq "$secs"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "$(t "$what を待ったが、${secs} 秒たっても終わらない（$DC logs で確かめる）" "gave up waiting for $what after ${secs} seconds (check with $DC logs)")"
}

for s in mtls-manager server-a server-b; do
  [ -n "$(dc ps -q --status running "$s")" ] || fail "$(t "$s が動いていない。先に $DC up -d --build を実行する" "$s is not running; run $DC up -d --build first")"
done
if m test -f /etc/mtls-ca/config.yaml; then
  fail "$(t "すでに設定済み。やり直すときは $DC down -v で消してから、$DC up -d --build と setup.sh を実行する" "already set up; to start over, remove everything with $DC down -v, then run $DC up -d --build and setup.sh")"
fi

step "$(t "1/5 ルート CA と中間 CA を作る（名前制約: $DOMAIN）" "1/5 Create the root CA and the intermediate CA (name constraint: $DOMAIN)")"
m mtlsctl root create -out-dir /var/lib/mtls-ca/offline -cn "Playground Root CA" -org "mtls-playground" -validity 2y
m mtlsctl intermediate csr -out-dir /etc/mtls-ca -cn "Playground mTLS CA" -org "mtls-playground"
m mtlsctl intermediate sign -root-cert /var/lib/mtls-ca/offline/root.crt -root-key /var/lib/mtls-ca/offline/root.key \
  -csr /etc/mtls-ca/intermediate.csr -out /etc/mtls-ca/intermediate.crt -permitted-domain "$DOMAIN" -validity 1y
m cp /var/lib/mtls-ca/offline/root.crt /etc/mtls-ca/root.crt

step "$(t "2/5 EAB 鍵を発行する（サーバごとに、取得できる名前を 1 つに限る）" "2/5 Issue EAB keys (each server may obtain exactly one name)")"
# kid はサーバごとの変数（KID_server_a など）に持つ。macOS の標準の bash 3.2 には連想配列（declare -A）が無いため。
set_kid() { printf -v "KID_${1//-/_}" '%s' "$2"; }
kid_of() { local v="KID_${1//-/_}"; printf '%s' "${!v}"; }
for name in server-a server-b admin; do
  fqdn=$name.$DOMAIN
  [ "$name" = admin ] && fqdn=$ADMIN
  out=$(m mtlsctl eab create -file /etc/mtls-ca/eab.json -names "$fqdn" -note "$name (playground)" -hmac-out "/etc/mtls-ca/$name.hmac")
  set_kid "$name" "$(printf '%s\n' "$out" | awk '$1 == "kid:" {print $2}')"
  [ -n "$(kid_of "$name")" ] || fail "$(t "EAB 鍵の kid を読み取れない: " "cannot read the EAB key kid: ")$out"
  echo "  $fqdn: kid=$(kid_of "$name")"
done

step "$(t "3/5 CA を起動する（ACME: https://$CA_HOST:8443、管理画面: https://$CA_HOST:9443）" "3/5 Start the CA (ACME: https://$CA_HOST:8443, admin UI: https://$CA_HOST:9443)")"
put mtls-manager /etc/mtls-ca/config.yaml 0600 <<EOF
listen: ":8443"
external_url: "https://$CA_HOST:8443"
data_dir: "/var/lib/mtls-ca"
root_cert: "/etc/mtls-ca/root.crt"
intermediate_cert: "/etc/mtls-ca/intermediate.crt"
intermediate_key: "/etc/mtls-ca/intermediate.key"
eab_file: "/etc/mtls-ca/eab.json"
policy:
  allowed_domains: ["$DOMAIN"]
cert:
  validity: "24h"
admin:
  listen: ":9443"
  allowed_clients: ["$ADMIN"]
  operators: ["$ADMIN"]
EOF
wait_for "$(t "CA の起動" "the CA to start")" 60 m curl -fsS --cacert /etc/mtls-ca/root.crt "https://$CA_HOST:8443/acme/directory"
echo "  $(t "CA が起動した" "the CA started")"

# agent_config 名前 FQDN 設定ディレクトリ アカウント鍵 後処理（YAML の配列）: mtls-agent の設定を出力する
agent_config() {
  cat <<EOF
ca_url: "https://$CA_HOST:8443/acme/directory"
ca_root: "$3/root.crt"
account_key: "$4"
eab:
  kid: "$(kid_of "$1")"
  hmac_file: "$3/eab.hmac"
names: ["$2"]
challenge:
  type: "http-01"
  listen: ":80"
output:
  cert: "$3/tls/cert.pem"
  chain: "$3/tls/chain.pem"
  fullchain: "$3/tls/fullchain.pem"
  key: "$3/tls/key.pem"
  ca: "$3/tls/ca.pem"
hooks:
  post_renew: $5
EOF
}

step "$(t "4/5 server-a / server-b に mtls-agent の設定を置く（各コンテナが証明書を取得し、アプリを起動する）" "4/5 Put the mtls-agent configuration on server-a / server-b (each container obtains a certificate and starts its application)")"
for name in server-a server-b; do
  hook='[]'
  [ "$name" = server-b ] && hook='["/bin/sh", "-c", "nginx -s reload 2>/dev/null || true"]'
  dc exec -T "$name" mkdir -p /etc/mtls-agent/tls
  m cat /etc/mtls-ca/root.crt | put "$name" /etc/mtls-agent/root.crt 0644
  m cat "/etc/mtls-ca/$name.hmac" | put "$name" /etc/mtls-agent/eab.hmac 0600
  # 設定ファイルを最後に置く（これを合図に、コンテナの中で mtls-agent が動き出す）
  agent_config "$name" "$name.$DOMAIN" /etc/mtls-agent /var/lib/mtls-agent/account.key "$hook" | put "$name" /etc/mtls-agent/config.yaml 0644
done
for name in server-a server-b; do
  wait_for "$(t "$name の証明書の取得" "$name to obtain its certificate")" 60 dc exec -T "$name" test -s /etc/mtls-agent/tls/fullchain.pem
  wait_for "$(t "$name のアプリの起動" "$name to start its application")" 30 dc exec -T "$name" sh -c 'curl -sk -o /dev/null https://localhost:8443/; [ $? -ne 7 ]'
  echo "  $name: $(t "証明書を取得し、アプリを起動した" "obtained its certificate and started its application")"
done

step "$(t "5/5 管理者の証明書を取得し、out/ に書き出す" "5/5 Obtain the administrator certificate and write it to out/")"
m mkdir -p /etc/mtls-agent-admin/tls
m cp /etc/mtls-ca/root.crt /etc/mtls-agent-admin/root.crt
m cp /etc/mtls-ca/admin.hmac /etc/mtls-agent-admin/eab.hmac
agent_config admin "$ADMIN" /etc/mtls-agent-admin /etc/mtls-agent-admin/account.key '[]' | put mtls-manager /etc/mtls-agent-admin/config.yaml 0644
# 取得と out/ への書き出しは renew-admin.sh と同じ（24 時間で切れた後の取り直しにも使う）
./renew-admin.sh --quiet
m rm -f /etc/mtls-ca/server-a.hmac /etc/mtls-ca/server-b.hmac /etc/mtls-ca/admin.hmac

if [ "$(t ja en)" = en ]; then
  cat <<EOF

$(printf '\033[32mSetup finished.\033[0m')
  Check:      ./check.sh
  Admin UI:   https://$CA_HOST:9443/ (see "4. Open the admin UI" in the README)
              import out/admin.p12 (password: $P12_PASS) into your browser, trust out/root.crt,
              and add "127.0.0.1 $CA_HOST" to hosts
EOF
else
  cat <<EOF

$(printf '\033[32m初期設定が終わった。\033[0m')
  動作確認:   ./check.sh
  管理画面:   https://$CA_HOST:9443/（手順は README の「4. 管理画面を開く」）
              out/admin.p12（パスワード: $P12_PASS）をブラウザに読み込み、out/root.crt を信頼し、
              hosts に「127.0.0.1 $CA_HOST」を加える
EOF
fi
