#!/bin/sh
# server-b: nginx。証明書は mtls-agent が更新し、更新の後に nginx を reload する（設定の hooks.post_renew）。
set -eu

/usr/local/bin/wait-and-run-agent.sh

exec nginx -g 'daemon off;'
