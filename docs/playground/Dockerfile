# mtls_manager の playground（体験用）のイメージ。compose.yaml から、リポジトリのルートを context にしてビルドする。
#   target manager  … mtls-ca（CA・管理画面）。初期設定の道具（mtlsctl・openssl）と、管理者の証明書の取得用の mtls-agent も入れる
#   target server-a … Go のアプリ（examples/go/server。mtls ライブラリを使う）＋ mtls-agent
#   target server-b … nginx ＋ mtls-agent
# 体験用なので、どのコンテナも root で動かし、アプリと mtls-agent を同じコンテナで動かす（本番の構成ではない）。

FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/ ./cmd/... ./examples/go/server

FROM debian:bookworm-slim AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl openssl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/mtls-agent /usr/local/bin/
COPY docs/playground/scripts/wait-and-run-agent.sh /usr/local/bin/

FROM base AS manager
COPY --from=build /out/mtls-ca /out/mtlsctl /usr/local/bin/
COPY docs/playground/manager/entrypoint.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

FROM base AS server-a
COPY --from=build /out/server /usr/local/bin/server-a
COPY docs/playground/server-a/entrypoint.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# nginx の公式イメージには curl が入っているので、追加のパッケージは要らない
FROM nginx:1.29-bookworm AS server-b
COPY --from=build /out/mtls-agent /usr/local/bin/
COPY docs/playground/scripts/wait-and-run-agent.sh /usr/local/bin/
COPY docs/playground/server-b/nginx.conf /etc/nginx/conf.d/default.conf
COPY docs/playground/server-b/entrypoint.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
