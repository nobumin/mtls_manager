package acmeserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/store"
	"github.com/nobumin/mtls_manager/internal/testca"
)

const web1 = "web1." + testca.Domain

func newClient(t *testing.T, ca *testca.CA) *acme.Client {
	t.Helper()
	key, err := pki.GenerateKey(pki.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return &acme.Client{Key: key, DirectoryURL: ca.DirectoryURL, HTTPClient: ca.HTTPClient()}
}

func register(t *testing.T, ctx context.Context, c *acme.Client, kid string, hmac []byte) {
	t.Helper()
	if _, err := c.Register(ctx, &acme.Account{ExternalAccountBinding: &acme.ExternalAccountBinding{KID: kid, Key: hmac}}, acme.AcceptTOS); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func problemType(err error) string {
	var ae *acme.Error
	if errors.As(err, &ae) {
		return ae.ProblemType
	}
	return ""
}

// serveHTTP01 は http-01 の応答を返すサーバを起動する。
func serveHTTP01(t *testing.T, c *acme.Client, token string) string {
	t.Helper()
	body, err := c.HTTP01ChallengeResponse(token)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != c.HTTP01ChallengePath(token) {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func issue(t *testing.T, ctx context.Context, ca *testca.CA, c *acme.Client, challengeType string, names ...string) []*x509.Certificate {
	t.Helper()
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := c.GetAuthorization(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		var chal *acme.Challenge
		for _, ch := range z.Challenges {
			if ch.Type == challengeType {
				chal = ch
			}
		}
		if chal == nil {
			t.Fatalf("%s のチャレンジが無い", challengeType)
		}
		switch challengeType {
		case config.ChallengeHTTP01:
			ca.SetTarget(config.ChallengeHTTP01, serveHTTP01(t, c, chal.Token))
		case config.ChallengeTLSALPN01:
			ca.SetTarget(config.ChallengeTLSALPN01, serveTLSALPN01(t, c, chal.Token, z.Identifier.Value))
		}
		if _, err := c.Accept(ctx, chal); err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if _, err := c.WaitAuthorization(ctx, u); err != nil {
			t.Fatalf("WaitAuthorization: %v", err)
		}
	}
	key, _ := pki.GenerateKey(pki.KeyECDSAP256)
	csr, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		t.Fatal(err)
	}
	ders, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("CreateOrderCert: %v", err)
	}
	var certs []*x509.Certificate
	for _, d := range ders {
		cert, err := x509.ParseCertificate(d)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
	}
	return certs
}

func serveTLSALPN01(t *testing.T, c *acme.Client, token, name string) string {
	t.Helper()
	cert, err := c.TLSALPN01ChallengeCert(token, name)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"acme-tls/1"}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestIssueWithHTTP01(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, hmac, _ := ca.AddEAB(t, web1)
	c := newClient(t, ca)
	register(t, ctx, c, kid, hmac)

	certs := issue(t, ctx, ca, c, config.ChallengeHTTP01, web1)
	if len(certs) != 2 {
		t.Fatalf("チェーンの枚数 = %d、want 2（末端 + 中間 CA）", len(certs))
	}
	inters := x509.NewCertPool()
	inters.AddCert(certs[1])
	for _, ku := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := certs[0].Verify(x509.VerifyOptions{Roots: ca.RootPool(), Intermediates: inters, DNSName: web1, KeyUsages: []x509.ExtKeyUsage{ku}}); err != nil {
			t.Errorf("用途 %v で検証に失敗: %v", ku, err)
		}
	}
	if d := time.Until(certs[0].NotAfter); d > 25*time.Hour {
		t.Errorf("有効期間が既定（24h）より長い: %v", d)
	}
}

func TestIssueWithTLSALPN01(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, hmac, _ := ca.AddEAB(t, "*."+testca.Domain)
	c := newClient(t, ca)
	register(t, ctx, c, kid, hmac)
	certs := issue(t, ctx, ca, c, config.ChallengeTLSALPN01, "a."+testca.Domain, "b."+testca.Domain)
	if got := certs[0].DNSNames; len(got) != 2 {
		t.Fatalf("DNSNames = %v", got)
	}
}

func TestRegisterRequiresValidEAB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, hmac, _ := ca.AddEAB(t, web1)

	c := newClient(t, ca)
	if _, err := c.Register(ctx, &acme.Account{}, acme.AcceptTOS); problemType(err) != "urn:ietf:params:acme:error:externalAccountRequired" {
		t.Errorf("EAB なしの登録: %v", err)
	}
	wrong := append([]byte(nil), hmac...)
	wrong[0] ^= 0xff
	if _, err := c.Register(ctx, &acme.Account{ExternalAccountBinding: &acme.ExternalAccountBinding{KID: kid, Key: wrong}}, acme.AcceptTOS); problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("誤った HMAC での登録: %v", err)
	}
	if _, err := c.Register(ctx, &acme.Account{ExternalAccountBinding: &acme.ExternalAccountBinding{KID: "unknown", Key: hmac}}, acme.AcceptTOS); problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("存在しない kid での登録: %v", err)
	}
	register(t, ctx, c, kid, hmac)
	// 同じ鍵での再登録は既存アカウントを返す。
	if _, err := c.Register(ctx, &acme.Account{ExternalAccountBinding: &acme.ExternalAccountBinding{KID: kid, Key: hmac}}, acme.AcceptTOS); !errors.Is(err, acme.ErrAccountAlreadyExists) {
		t.Errorf("再登録: %v", err)
	}
	if _, err := c.GetReg(ctx, ""); err != nil {
		t.Errorf("GetReg: %v", err)
	}
}

func TestOrderRejectsNamesOutsidePolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, hmac, _ := ca.AddEAB(t, web1)
	c := newClient(t, ca)
	register(t, ctx, c, kid, hmac)

	for _, n := range []string{
		"web2." + testca.Domain, // EAB 鍵で許可されていない
		"web1.example.org",      // CA のドメインの範囲外
		"*." + testca.Domain,    // ワイルドカード
	} {
		_, err := c.AuthorizeOrder(ctx, acme.DomainIDs(n))
		if pt := problemType(err); pt != "urn:ietf:params:acme:error:rejectedIdentifier" {
			t.Errorf("%s: problem = %q（err = %v）", n, pt, err)
		}
	}
	if _, err := c.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "ip", Value: "10.0.0.1"}}); problemType(err) != "urn:ietf:params:acme:error:unsupportedIdentifier" {
		t.Errorf("IP の識別子: %v", err)
	}
}

func TestRemovedEABBlocksNewOrders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, hmac, _ := ca.AddEAB(t, web1)
	c := newClient(t, ca)
	register(t, ctx, c, kid, hmac)
	ca.RemoveEAB(t, kid)
	if _, err := c.AuthorizeOrder(ctx, acme.DomainIDs(web1)); problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("EAB 鍵の取り消し後に注文できた: %v", err)
	}
}

func TestFailedChallengeInvalidatesAuthz(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, hmac, _ := ca.AddEAB(t, web1)
	c := newClient(t, ca)
	register(t, ctx, c, kid, hmac)

	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(web1))
	if err != nil {
		t.Fatal(err)
	}
	z, err := c.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	var chal *acme.Challenge
	for _, ch := range z.Challenges {
		if ch.Type == config.ChallengeHTTP01 {
			chal = ch
		}
	}
	// 別のトークンの応答を返す（正しい鍵を持たないホストを模す）。
	ca.SetTarget(config.ChallengeHTTP01, serveHTTP01(t, c, "wrong-token"))
	if _, err := c.Accept(ctx, chal); err != nil {
		t.Fatal(err)
	}
	_, err = c.WaitAuthorization(ctx, order.AuthzURLs[0])
	var ae *acme.AuthorizationError
	if !errors.As(err, &ae) {
		t.Fatalf("所有確認の失敗が返らない: %v", err)
	}
	// 失敗した注文は発行できない。
	key, _ := pki.GenerateKey(pki.KeyECDSAP256)
	csr, _ := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{DNSNames: []string{web1}}, key)
	if _, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csr, true); problemType(err) != "urn:ietf:params:acme:error:orderNotReady" {
		t.Fatalf("失敗した注文で発行できた: %v", err)
	}
}

func TestFinalizeRejectsMismatchedCSR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, hmac, _ := ca.AddEAB(t, "*."+testca.Domain)
	c := newClient(t, ca)
	register(t, ctx, c, kid, hmac)
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(web1))
	if err != nil {
		t.Fatal(err)
	}
	z, _ := c.GetAuthorization(ctx, order.AuthzURLs[0])
	for _, ch := range z.Challenges {
		if ch.Type == config.ChallengeHTTP01 {
			ca.SetTarget(config.ChallengeHTTP01, serveHTTP01(t, c, ch.Token))
			if _, err := c.Accept(ctx, ch); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := c.WaitAuthorization(ctx, order.AuthzURLs[0]); err != nil {
		t.Fatal(err)
	}
	key, _ := pki.GenerateKey(pki.KeyECDSAP256)
	csr, _ := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "web2." + testca.Domain},
		DNSNames: []string{web1},
	}, key)
	if _, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csr, true); problemType(err) != "urn:ietf:params:acme:error:badCSR" {
		t.Fatalf("注文と異なる名前の CSR で発行できた: %v", err)
	}
}

func TestRevokeAndCRL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, hmac, _ := ca.AddEAB(t, web1)
	c := newClient(t, ca)
	register(t, ctx, c, kid, hmac)
	certs := issue(t, ctx, ca, c, config.ChallengeHTTP01, web1)

	// 他のアカウントは失効できない。
	other := newClient(t, ca)
	kid2, hmac2, _ := ca.AddEAB(t, "other."+testca.Domain)
	register(t, ctx, other, kid2, hmac2)
	if err := other.RevokeCert(ctx, nil, certs[0].Raw, acme.CRLReasonKeyCompromise); problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("他のアカウントで失効できた: %v", err)
	}

	if err := c.RevokeCert(ctx, nil, certs[0].Raw, acme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	// 二重の失効はサーバが alreadyRevoked を返し、x/crypto/acme はそれを成功として扱う。
	if err := c.RevokeCert(ctx, nil, certs[0].Raw, acme.CRLReasonKeyCompromise); err != nil {
		t.Errorf("二重の失効: %v", err)
	}

	res, err := ca.HTTPClient().Get(ca.URL + "/crl")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	der, _ := io.ReadAll(res.Body)
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(ca.Issuer.Cert); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(certs[0].SerialNumber) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("失効した証明書が CRL に載っていない")
	}
}

// 管理画面からの失効（RevokeByAdmin）も、すぐに CRL に反映される。
func TestRevokeByAdminUpdatesCRL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca := testca.Start(t, nil)
	kid, hmac, _ := ca.AddEAB(t, web1)
	c := newClient(t, ca)
	register(t, ctx, c, kid, hmac)
	certs := issue(t, ctx, ca, c, config.ChallengeHTTP01, web1)

	crlHas := func() bool {
		t.Helper()
		res, err := ca.HTTPClient().Get(ca.URL + "/crl")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		der, _ := io.ReadAll(res.Body)
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(certs[0].SerialNumber) == 0 {
				return true
			}
		}
		return false
	}
	if crlHas() { // ここで CRL が作られ、キャッシュされる
		t.Fatal("失効前の CRL に載っている")
	}
	serial := fmt.Sprintf("%x", certs[0].SerialNumber)
	if err := ca.Server.RevokeByAdmin(serial, 4); err != nil {
		t.Fatal(err)
	}
	if !crlHas() {
		t.Fatal("管理画面からの失効が CRL に反映されない")
	}
	if err := ca.Server.RevokeByAdmin(serial, 4); !errors.Is(err, store.ErrAlreadyRevoked) {
		t.Errorf("二重の失効: %v", err)
	}
}

func TestSourceRestriction(t *testing.T) {
	ca := testca.Start(t, func(c *config.CA) { c.AllowedClientCIDRs = []string{"10.0.0.0/8"} })
	res, err := ca.HTTPClient().Get(ca.DirectoryURL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("許可されていない送信元からの接続のステータス = %d", res.StatusCode)
	}
}

func TestRejectsReplayedNonce(t *testing.T) {
	ca := testca.Start(t, nil)
	hc := ca.HTTPClient()
	// JWS の形をしていないリクエストは malformed で、Replay-Nonce が付く。
	res, err := hc.Post(ca.URL+"/acme/new-account", "application/jose+json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || res.Header.Get("Replay-Nonce") == "" {
		t.Fatalf("status = %d nonce = %q", res.StatusCode, res.Header.Get("Replay-Nonce"))
	}
	res, err = hc.Post(ca.URL+"/acme/new-account", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("Content-Type 違いの status = %d", res.StatusCode)
	}
}
