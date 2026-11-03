package acmeserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/asn1"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nobumin/mtls_manager/internal/i18n"
)

// id-pe-acmeIdentifier（RFC 8737 §3）
var oidACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

const alpnACME = "acme-tls/1"

// Validator はチャレンジ（所有確認）を実行する。
type Validator struct {
	HTTPPort    int
	TLSALPNPort int
	Timeout     time.Duration
	// Resolver は名前解決に使う DNS サーバ（"host:port"）。空なら OS の設定。
	Resolver string
	// DialContext を差し替えると接続先を変えられる（テスト用）。
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (v *Validator) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if v.DialContext != nil {
		return v.DialContext(ctx, network, addr)
	}
	d := &net.Dialer{Timeout: v.Timeout}
	if v.Resolver != "" {
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: v.Timeout}).DialContext(ctx, network, v.Resolver)
			},
		}
	}
	return d.DialContext(ctx, network, addr)
}

// validateHTTP01 は http://<name>:<port>/.well-known/acme-challenge/<token> の応答を確かめる（RFC 8555 §8.3）。
// リダイレクトは追わない（社内ネットワークで別のホストへ誘導されないようにする）。
func (v *Validator) validateHTTP01(ctx context.Context, name, token, keyAuth string) *problem {
	ctx, cancel := context.WithTimeout(ctx, v.Timeout)
	defer cancel()
	host := name
	if v.HTTPPort != 80 {
		host = net.JoinHostPort(name, strconv.Itoa(v.HTTPPort))
	}
	u := "http://" + host + "/.well-known/acme-challenge/" + token
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             nil, // 環境変数のプロキシを使わない
			DialContext:       v.dial,
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return malformed("%s", i18n.T("URL を組み立てられない", "cannot build the URL"))
	}
	res, err := client.Do(req)
	if err != nil {
		return connectionProblem(name, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return newProblem(http.StatusForbidden, "incorrectResponse", i18n.T("%s がステータス %d を返した", "%s returned status %d"), u, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<10))
	if err != nil {
		return connectionProblem(name, err)
	}
	if subtle.ConstantTimeCompare(bytes.TrimSpace(body), []byte(keyAuth)) != 1 {
		return newProblem(http.StatusForbidden, "incorrectResponse", i18n.T("%s の応答内容が一致しない", "the response from %s does not match"), u)
	}
	return nil
}

// validateTLSALPN01 は acme-tls/1 で接続し、提示された証明書を確かめる（RFC 8737）。
func (v *Validator) validateTLSALPN01(ctx context.Context, name, keyAuth string) *problem {
	ctx, cancel := context.WithTimeout(ctx, v.Timeout)
	defer cancel()
	raw, err := v.dial(ctx, "tcp", net.JoinHostPort(name, strconv.Itoa(v.TLSALPNPort)))
	if err != nil {
		return connectionProblem(name, err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		ServerName: name,
		NextProtos: []string{alpnACME},
		MinVersion: tls.VersionTLS12,
		// 提示される証明書は検証用の自己署名なので、チェーンの検証はせず中身を確かめる。
		InsecureSkipVerify: true, //nolint:gosec // RFC 8737 のとおり
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return newProblem(http.StatusForbidden, "tls", i18n.T("%s と TLS 接続できない: %v", "cannot establish a TLS connection to %s: %v"), name, err)
	}
	st := conn.ConnectionState()
	if st.NegotiatedProtocol != alpnACME {
		return newProblem(http.StatusForbidden, "tls", i18n.T("%s が acme-tls/1 を選ばなかった", "%s did not select acme-tls/1"), name)
	}
	if len(st.PeerCertificates) == 0 {
		return newProblem(http.StatusForbidden, "tls", i18n.T("%s が証明書を提示しなかった", "%s presented no certificate"), name)
	}
	c := st.PeerCertificates[0]
	if len(c.DNSNames) != 1 || !strings.EqualFold(c.DNSNames[0], name) ||
		len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) != 0 {
		return newProblem(http.StatusForbidden, "incorrectResponse", i18n.T("%s の検証用証明書の名前が不正", "the validation certificate from %s has invalid names"), name)
	}
	want := sha256.Sum256([]byte(keyAuth))
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidACMEIdentifier) {
			continue
		}
		if !ext.Critical {
			return newProblem(http.StatusForbidden, "incorrectResponse", "%s", i18n.T("acmeIdentifier 拡張が critical ではない", "the acmeIdentifier extension is not critical"))
		}
		var got []byte
		if rest, err := asn1.Unmarshal(ext.Value, &got); err != nil || len(rest) != 0 {
			return newProblem(http.StatusForbidden, "incorrectResponse", "%s", i18n.T("acmeIdentifier 拡張を解釈できない", "cannot parse the acmeIdentifier extension"))
		}
		if subtle.ConstantTimeCompare(got, want[:]) != 1 {
			return newProblem(http.StatusForbidden, "incorrectResponse", "%s", i18n.T("acmeIdentifier が一致しない", "acmeIdentifier does not match"))
		}
		return nil
	}
	return newProblem(http.StatusForbidden, "incorrectResponse", "%s", i18n.T("acmeIdentifier 拡張が無い", "no acmeIdentifier extension"))
}

func connectionProblem(name string, err error) *problem {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return newProblem(http.StatusForbidden, "dns", i18n.T("%s を名前解決できない: %v", "cannot resolve %s: %v"), name, dnsErr)
	}
	return newProblem(http.StatusForbidden, "connection", i18n.T("%s に接続できない: %s", "cannot connect to %s: %s"), name, shortErr(err))
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
