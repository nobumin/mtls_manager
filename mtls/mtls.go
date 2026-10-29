// Package mtls は mtls_manager で発行した証明書を使って、Go のアプリに mTLS を組み込むためのライブラリ。
//
//   - 証明書・鍵のファイルが mtls-agent によって更新されると、再起動なしで新しいものを使う
//   - サーバ側はクライアント証明書を必須にし、相手の名前を許可リストで確かめる
//   - 既定で TLS 1.3 以上
//
// サーバの例:
//
//	cfg, err := mtls.NewServerTLSConfig(mtls.Config{
//		CertFile:     "/etc/mtls-agent/tls/fullchain.pem",
//		KeyFile:      "/etc/mtls-agent/tls/key.pem",
//		CAFile:       "/etc/mtls-agent/tls/ca.pem",
//		AllowedPeers: []string{"app1.internal.example.com", "*.batch.internal.example.com"},
//	})
//	srv := &http.Server{Addr: ":8443", TLSConfig: cfg, Handler: h}
//	log.Fatal(srv.ListenAndServeTLS("", ""))
//
// クライアントの例:
//
//	cfg, err := mtls.NewClientTLSConfig(mtls.Config{
//		CertFile: "/etc/mtls-agent/tls/fullchain.pem",
//		KeyFile:  "/etc/mtls-agent/tls/key.pem",
//		CAFile:   "/etc/mtls-agent/tls/ca.pem",
//	})
//	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
//	res, err := client.Get("https://api.internal.example.com:8443/")
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nobumin/mtls_manager/internal/names"
)

// Config は mTLS の設定。
type Config struct {
	// CertFile は証明書のファイル。中間 CA を含む fullchain を指定する
	// （相手が中間 CA を持っていなくてもチェーンを組めるようにするため）。
	CertFile string
	// KeyFile は秘密鍵のファイル。
	KeyFile string
	// CAFile は信頼するルート CA の証明書。
	CAFile string

	// AllowedPeers は接続を許可する相手の名前のパターン（証明書の DNS 名と照合する）。
	//   "app1.internal.example.com" … 完全一致
	//   "*.internal.example.com"    … 直下の 1 ラベルに一致
	// サーバ側では必須（AllowAnyPeer を true にしない限り）。クライアント側では任意で、
	// 指定するとホスト名の検証に加えて相手の名前を確かめる。
	AllowedPeers []string
	// AllowAnyPeer を true にすると、同じ CA が発行した証明書を持つ相手をすべて許可する（非推奨）。
	// TrustBundleFile を指定しても、AllowAnyPeer が効くのは自分のルート CA につながる相手だけ（連携先の相手は AllowedPeers に一致すること）。
	AllowAnyPeer bool

	// TrustBundleFile は連携版のトラストバンドル（mtls-agent の output.trust_bundle）。指定すると、CAFile のルート CA に加えて、
	// 承認済みの連携先のルート CA を、その範囲の名前に限って信頼する（任意）。CertFile には fullchain を指定する。
	// クライアント側では、ホスト名（DNS 名）で接続する（IP アドレスでの接続はホスト名を確かめられないので拒否する）。
	TrustBundleFile string
	// OwnDomains は自分の範囲を狭める（任意）。自分の範囲は自分の中間 CA の名前制約から得るので、通常は指定しない。
	// 名前制約より広い値は使えない。
	OwnDomains []string

	// MinVersion は TLS の最低バージョン。既定 tls.VersionTLS13。
	MinVersion uint16
	// ReloadInterval は証明書ファイルの更新を確かめる間隔。既定 30 秒。
	ReloadInterval time.Duration
	// Logger は証明書の再読み込みの成否を記録する。nil なら slog.Default()。
	Logger *slog.Logger
}

func (c *Config) defaults() error {
	if c.CertFile == "" || c.KeyFile == "" || c.CAFile == "" {
		return errors.New("mtls: CertFile / KeyFile / CAFile は必須")
	}
	if c.MinVersion == 0 {
		c.MinVersion = tls.VersionTLS13
	}
	if c.MinVersion < tls.VersionTLS12 {
		return errors.New("mtls: MinVersion は TLS 1.2 以上")
	}
	if c.ReloadInterval == 0 {
		c.ReloadInterval = 30 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	norm := make([]string, 0, len(c.AllowedPeers))
	for _, p := range c.AllowedPeers {
		p = names.Normalize(p)
		if err := names.ValidatePattern(p); err != nil {
			return fmt.Errorf("mtls: AllowedPeers: %w", err)
		}
		norm = append(norm, p)
	}
	c.AllowedPeers = norm
	return nil
}

// NewServerTLSConfig はクライアント証明書を必須にするサーバ用の tls.Config を作る。
func NewServerTLSConfig(c Config) (*tls.Config, error) {
	if err := c.defaults(); err != nil {
		return nil, err
	}
	if len(c.AllowedPeers) == 0 && !c.AllowAnyPeer {
		return nil, errors.New("mtls: サーバ側は AllowedPeers で接続を許可する相手を指定する（すべて許可するなら AllowAnyPeer）")
	}
	pool, err := LoadCAPool(c.CAFile)
	if err != nil {
		return nil, err
	}
	src, err := NewSource(c.CertFile, c.KeyFile, c.ReloadInterval, c.Logger)
	if err != nil {
		return nil, err
	}
	if c.TrustBundleFile != "" {
		ts, err := newTrustStore(c, src)
		if err != nil {
			return nil, err
		}
		// チェーンの検証は VerifyConnection で行う（連携先のルートと範囲を、その時点のバンドルで確かめるため）。
		return &tls.Config{
			MinVersion:       c.MinVersion,
			ClientAuth:       tls.RequireAnyClientCert,
			GetCertificate:   src.GetCertificate,
			VerifyConnection: ts.verifyConnection(true, c.AllowedPeers),
		}, nil
	}
	cfg := &tls.Config{
		MinVersion:     c.MinVersion,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      pool,
		GetCertificate: src.GetCertificate,
	}
	if len(c.AllowedPeers) > 0 {
		cfg.VerifyConnection = VerifyPeer(c.AllowedPeers)
	}
	return cfg, nil
}

// NewClientTLSConfig はクライアント証明書を提示するクライアント用の tls.Config を作る。
// 接続先のホスト名の検証は通常の TLS と同じく行う。
func NewClientTLSConfig(c Config) (*tls.Config, error) {
	if err := c.defaults(); err != nil {
		return nil, err
	}
	pool, err := LoadCAPool(c.CAFile)
	if err != nil {
		return nil, err
	}
	src, err := NewSource(c.CertFile, c.KeyFile, c.ReloadInterval, c.Logger)
	if err != nil {
		return nil, err
	}
	if c.TrustBundleFile != "" {
		ts, err := newTrustStore(c, src)
		if err != nil {
			return nil, err
		}
		// 標準の検証の代わりに、VerifyConnection でホスト名を含めて検証する（Go の推奨する方法）。
		return &tls.Config{
			MinVersion:           c.MinVersion,
			InsecureSkipVerify:   true,
			GetClientCertificate: src.GetClientCertificate,
			VerifyConnection:     ts.verifyConnection(false, c.AllowedPeers),
		}, nil
	}
	cfg := &tls.Config{
		MinVersion:           c.MinVersion,
		RootCAs:              pool,
		GetClientCertificate: src.GetClientCertificate,
	}
	if len(c.AllowedPeers) > 0 {
		cfg.VerifyConnection = VerifyPeer(c.AllowedPeers)
	}
	return cfg, nil
}

// LoadCAPool はルート CA の証明書ファイルを読んでプールにする。OS の信頼ストアは使わない。
func LoadCAPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("mtls: %s に証明書が無い", path)
	}
	return pool, nil
}

// VerifyPeer は相手の証明書の DNS 名がいずれかのパターンに一致することを確かめる関数を返す。
// tls.Config.VerifyConnection に設定する。チェーンの検証は tls パッケージが先に済ませている前提。
func VerifyPeer(patterns []string) func(tls.ConnectionState) error {
	patterns = slices.Clone(patterns)
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("mtls: 相手が証明書を提示しなかった")
		}
		for _, n := range cs.PeerCertificates[0].DNSNames {
			if names.MatchAny(patterns, names.Normalize(n)) {
				return nil
			}
		}
		return fmt.Errorf("mtls: 相手 %v は許可されていない", cs.PeerCertificates[0].DNSNames)
	}
}

// PeerNames は検証済みの相手の DNS 名を返す（http.Request.TLS を渡す）。
// アプリ側で相手ごとに処理を分けるときに使う。
func PeerNames(cs *tls.ConnectionState) []string {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		return nil
	}
	out := make([]string, 0, len(cs.PeerCertificates[0].DNSNames))
	for _, n := range cs.PeerCertificates[0].DNSNames {
		out = append(out, strings.ToLower(n))
	}
	return out
}

// Source は証明書と鍵のファイルを読み、更新されたら読み直す。
type Source struct {
	certFile, keyFile string
	interval          time.Duration
	log               *slog.Logger

	cur atomic.Pointer[tls.Certificate]

	mu        sync.Mutex
	lastCheck time.Time
	stamp     string
}

// NewSource は証明書と鍵を読み込む。読めなければエラー。
func NewSource(certFile, keyFile string, interval time.Duration, log *slog.Logger) (*Source, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Source{certFile: certFile, keyFile: keyFile, interval: interval, log: log}
	stamp, err := s.fileStamp()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: 証明書を読めない: %w", err)
	}
	s.cur.Store(&cert)
	s.stamp, s.lastCheck = stamp, time.Now()
	return s, nil
}

func (s *Source) fileStamp() (string, error) {
	var b strings.Builder
	for _, p := range []string{s.certFile, s.keyFile} {
		fi, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%d:%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	return b.String(), nil
}

// Certificate は現在の証明書を返す。間隔が過ぎていればファイルの更新を確かめる。
// 読み直しに失敗したとき（書き換えの途中で証明書と鍵が対応していない等）は、直前の証明書を使い続ける。
func (s *Source) Certificate() *tls.Certificate {
	s.mu.Lock()
	if time.Since(s.lastCheck) >= s.interval {
		s.lastCheck = time.Now()
		s.reloadLocked()
	}
	s.mu.Unlock()
	return s.cur.Load()
}

// Reload はすぐにファイルの更新を確かめる。
func (s *Source) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCheck = time.Now()
	s.reloadLocked()
}

func (s *Source) reloadLocked() {
	stamp, err := s.fileStamp()
	if err != nil {
		s.log.Warn("mtls: 証明書ファイルを確認できない（直前の証明書を使い続ける）", "err", err)
		return
	}
	if stamp == s.stamp {
		return
	}
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		s.log.Warn("mtls: 証明書を読み直せない（直前の証明書を使い続ける）", "err", err)
		return
	}
	s.cur.Store(&cert)
	s.stamp = stamp
	if cert.Leaf != nil {
		s.log.Info("mtls: 証明書を読み直した", "names", cert.Leaf.DNSNames, "not_after", cert.Leaf.NotAfter)
	}
}

// GetCertificate は tls.Config.GetCertificate に設定する。
func (s *Source) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.Certificate(), nil
}

// GetClientCertificate は tls.Config.GetClientCertificate に設定する。
func (s *Source) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return s.Certificate(), nil
}
