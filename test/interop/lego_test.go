//go:build interop

// Package interop は外部の ACME クライアント（lego）との相互接続を試験する。
//
//	go test -tags interop ./test/interop/ （環境変数 LEGO_BIN に lego のパスを指定）
//
// CA のホスト名 ca.internal.example.com と web1.internal.example.com が 127.0.0.1 に名前解決できること
// （CI では /etc/hosts に追記する）。
package interop

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/testca"
)

const web1 = "web1." + testca.Domain

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestLego(t *testing.T) {
	bin := os.Getenv("LEGO_BIN")
	if bin == "" {
		t.Skip("LEGO_BIN が未設定")
	}
	if addrs, err := net.LookupHost("ca." + testca.Domain); err != nil || len(addrs) == 0 {
		t.Fatalf("ca.%s を名前解決できない（/etc/hosts に 127.0.0.1 を追記する）: %v", testca.Domain, err)
	}
	httpPort, tlsPort := freePort(t), freePort(t)
	ca := testca.Start(t, func(c *config.CA) {
		c.Challenge.HTTP01Port = httpPort
		c.Challenge.TLSALPN01Port = tlsPort
	})
	ca.SetTarget(config.ChallengeHTTP01, "127.0.0.1:"+strconv.Itoa(httpPort))
	ca.SetTarget(config.ChallengeTLSALPN01, "127.0.0.1:"+strconv.Itoa(tlsPort))
	kid, _, hmac := ca.AddEAB(t, web1)
	dir := t.TempDir()

	lego := func(args ...string) {
		t.Helper()
		base := []string{
			"--server", ca.DirectoryURL, "--accept-tos", "--email", "ops@" + testca.Domain,
			"--eab", "--kid", kid, "--hmac", hmac, "--domains", web1, "--path", dir,
		}
		cmd := exec.Command(bin, append(base, args...)...)
		cmd.Env = append(os.Environ(), "LEGO_CA_CERTIFICATES="+ca.RootFile, "NO_PROXY="+testca.Domain, "no_proxy="+testca.Domain)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("lego %v: %v\n%s", args, err, out)
		}
	}
	certPath := filepath.Join(dir, "certificates", web1+".crt")
	serialOf := func() string {
		t.Helper()
		certs, err := pki.LoadCerts(certPath)
		if err != nil {
			t.Fatal(err)
		}
		return certs[0].SerialNumber.String()
	}

	lego("--http", "--http.port", "127.0.0.1:"+strconv.Itoa(httpPort), "run")
	first := serialOf()
	lego("--tls", "--tls.port", "127.0.0.1:"+strconv.Itoa(tlsPort), "renew", "--days", "30", "--no-random-sleep")
	if serialOf() == first {
		t.Fatal("renew で証明書が更新されていない")
	}
	lego("revoke")
}
