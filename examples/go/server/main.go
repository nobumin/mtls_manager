// mTLS で待ち受ける HTTP サーバの例。証明書は mtls-agent が更新し、このプロセスは再起動なしで追従する。
//
//	go run ./examples/go/server -cert /etc/mtls-agent/tls/fullchain.pem -key /etc/mtls-agent/tls/key.pem \
//	    -ca /etc/mtls-agent/tls/ca.pem -allow 'app1.internal.example.com,*.batch.internal.example.com'
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/nobumin/mtls_manager/mtls"
)

func main() {
	addr := flag.String("addr", ":8443", "待ち受けアドレス")
	cert := flag.String("cert", "/etc/mtls-agent/tls/fullchain.pem", "証明書（fullchain）")
	key := flag.String("key", "/etc/mtls-agent/tls/key.pem", "秘密鍵")
	ca := flag.String("ca", "/etc/mtls-agent/tls/ca.pem", "ルート CA")
	allow := flag.String("allow", "", "接続を許可する相手（カンマ区切りのパターン）")
	flag.Parse()

	cfg, err := mtls.NewServerTLSConfig(mtls.Config{
		CertFile: *cert, KeyFile: *key, CAFile: *ca,
		AllowedPeers: strings.Split(*allow, ","),
	})
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:      *addr,
		TLSConfig: cfg,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// mtls.PeerNames で、検証済みの相手の名前が分かる。
			fmt.Fprintf(w, "hello, %v\n", mtls.PeerNames(r.TLS))
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
