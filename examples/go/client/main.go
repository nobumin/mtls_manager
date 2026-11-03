// mTLS で接続する HTTP クライアントの例。
//
//	go run ./examples/go/client -cert /etc/mtls-agent/tls/fullchain.pem -key /etc/mtls-agent/tls/key.pem \
//	    -ca /etc/mtls-agent/tls/ca.pem https://api.internal.example.com:8443/
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nobumin/mtls_manager/mtls"
)

func main() {
	cert := flag.String("cert", "/etc/mtls-agent/tls/fullchain.pem", "証明書（fullchain）")
	key := flag.String("key", "/etc/mtls-agent/tls/key.pem", "秘密鍵")
	ca := flag.String("ca", "/etc/mtls-agent/tls/ca.pem", "ルート CA")
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("接続先の URL を 1 つ指定する")
	}

	cfg, err := mtls.NewClientTLSConfig(mtls.Config{CertFile: *cert, KeyFile: *key, CAFile: *ca})
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
	res, err := client.Get(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(os.Stdout, res.Body)
}
