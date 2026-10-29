package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"github.com/nobumin/mtls_manager/internal/names"
)

// チャレンジの種類。
const (
	ChallengeHTTP01    = "http-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
)

// CA は mtls-ca の設定。
type CA struct {
	// Listen は待ち受けアドレス。既定 ":8443"。
	Listen string `yaml:"listen"`
	// ExternalURL はクライアントから見た CA の URL（例: https://ca.internal.example.com:8443）。
	// ACME の各 URL と、JWS の "url" ヘッダの照合に使う。
	ExternalURL string `yaml:"external_url"`
	// Hostnames は CA 自身の TLS サーバ証明書に載せる名前。既定は ExternalURL のホスト名。
	Hostnames []string `yaml:"hostnames"`
	// DataDir はアカウント・注文・発行履歴のデータベースを置くディレクトリ。
	DataDir string `yaml:"data_dir"`

	RootCert         string `yaml:"root_cert"`
	IntermediateCert string `yaml:"intermediate_cert"`
	IntermediateKey  string `yaml:"intermediate_key"`
	// EABFile は External Account Binding の鍵ファイル（mtlsctl eab で管理。権限 0600 必須）。
	EABFile string `yaml:"eab_file"`

	// AllowedClientCIDRs は CA に接続できる送信元。空なら制限しない（非推奨）。
	AllowedClientCIDRs []string `yaml:"allowed_client_cidrs"`

	Policy    CAPolicy    `yaml:"policy"`
	Cert      CACert      `yaml:"cert"`
	Challenge CAChallenge `yaml:"challenge"`
	CRL       CACRL       `yaml:"crl"`
	Admin     CAAdmin     `yaml:"admin"`
	Log       Log         `yaml:"log"`

	allowedPrefixes []netip.Prefix
}

// CAAdmin は管理画面（閲覧用の Web 画面）の設定。Listen が空なら無効。
type CAAdmin struct {
	// Listen は管理画面の待ち受けアドレス。ACME とは別のポートにし、localhost か管理用のサブネットの
	// アドレスで待ち受ける（例: "127.0.0.1:9443"、"10.0.100.5:9443"）。空なら管理画面を起動しない。
	Listen string `yaml:"listen"`
	// AllowedClients は管理画面に入れる管理者の証明書の名前（パターン）。Listen を指定したら必須。
	// 管理者は、この CA が発行したクライアント証明書でログインする（mTLS）。パスワードは使わない。
	AllowedClients []string `yaml:"allowed_clients"`
	// AllowedCIDRs は管理画面に接続できる送信元。空なら制限しない（Listen のアドレスで絞る）。
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
	// LogBuffer は管理画面で閲覧できるログの件数（メモリに保持する直近の分）。既定 5000。
	LogBuffer int `yaml:"log_buffer"`

	allowedPrefixes []netip.Prefix
}

// AllowedPrefixes は解釈済みの送信元制限を返す。
func (a CAAdmin) AllowedPrefixes() []netip.Prefix { return a.allowedPrefixes }

// CAPolicy は発行してよい名前の方針。
type CAPolicy struct {
	// AllowedDomains は発行してよいドメイン（そのドメイン自身とサブドメイン）。必須。
	AllowedDomains []string `yaml:"allowed_domains"`
	// MaxNamesPerOrder は 1 枚の証明書に載せられる名前の上限。既定 10。
	MaxNamesPerOrder int `yaml:"max_names_per_order"`
}

// CACert は発行する証明書の条件。
type CACert struct {
	// Validity は末端の証明書の有効期間。既定 24h。
	Validity Duration `yaml:"validity"`
}

// CAChallenge は所有確認（チャレンジ）の条件。
type CAChallenge struct {
	// Types は受け付けるチャレンジ。既定 [http-01, tls-alpn-01]。
	Types []string `yaml:"types"`
	// HTTP01Port は http-01 で接続するポート。既定 80。
	HTTP01Port int `yaml:"http01_port"`
	// TLSALPN01Port は tls-alpn-01 で接続するポート。既定 443。
	TLSALPN01Port int `yaml:"tlsalpn01_port"`
	// Resolver は名前解決に使う DNS サーバ（例: "10.0.0.2:53"）。空なら OS の設定。
	Resolver string `yaml:"resolver"`
	// Timeout は 1 回の確認の制限時間。既定 10s。
	Timeout Duration `yaml:"timeout"`
	// Attempts は失敗とみなすまでの試行回数。既定 3。
	Attempts int `yaml:"attempts"`
}

// CACRL は CRL の条件。
type CACRL struct {
	// Validity は CRL の NextUpdate までの期間。既定 24h。
	Validity Duration `yaml:"validity"`
}

// Log はログ出力の条件。
type Log struct {
	// Level は debug / info / warn / error。既定 info。
	Level string `yaml:"level"`
	// Format は text / json。既定 text。
	Format string `yaml:"format"`
}

// LoadCA は設定を読み、既定値を補って検証する。
func LoadCA(path string) (*CA, error) {
	c := &CA{}
	if err := load(path, c); err != nil {
		return nil, err
	}
	if err := c.Complete(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Complete は既定値を補って検証する。
func (c *CA) Complete() error {
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.ExternalURL == "" {
		return errors.New("external_url は必須")
	}
	u, err := url.Parse(c.ExternalURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return fmt.Errorf("external_url %q は https://ホスト[:ポート] の形にする", c.ExternalURL)
	}
	c.ExternalURL = u.Scheme + "://" + u.Host
	if len(c.Hostnames) == 0 {
		c.Hostnames = []string{u.Hostname()}
	}
	for i, h := range c.Hostnames {
		h = names.Normalize(h)
		if err := names.ValidateHostname(h); err != nil {
			return fmt.Errorf("hostnames: %w", err)
		}
		c.Hostnames[i] = h
	}
	for _, f := range []struct{ name, v string }{
		{"data_dir", c.DataDir}, {"root_cert", c.RootCert}, {"intermediate_cert", c.IntermediateCert},
		{"intermediate_key", c.IntermediateKey}, {"eab_file", c.EABFile},
	} {
		if f.v == "" {
			return fmt.Errorf("%s は必須", f.name)
		}
	}
	if c.allowedPrefixes, err = parsePrefixes("allowed_client_cidrs", c.AllowedClientCIDRs); err != nil {
		return err
	}

	if len(c.Policy.AllowedDomains) == 0 {
		return errors.New("policy.allowed_domains は必須（発行してよいドメインを限定する）")
	}
	for i, d := range c.Policy.AllowedDomains {
		d = names.Normalize(d)
		if err := names.ValidateDomain(d); err != nil {
			return fmt.Errorf("policy.allowed_domains: %w", err)
		}
		c.Policy.AllowedDomains[i] = d
	}
	if c.Policy.MaxNamesPerOrder == 0 {
		c.Policy.MaxNamesPerOrder = 10
	}
	if c.Policy.MaxNamesPerOrder < 1 || c.Policy.MaxNamesPerOrder > 100 {
		return errors.New("policy.max_names_per_order は 1〜100")
	}

	if c.Cert.Validity == 0 {
		c.Cert.Validity = Duration(24 * time.Hour)
	}
	if v := c.Cert.Validity.D(); v < 10*time.Minute || v > 90*24*time.Hour {
		return errors.New("cert.validity は 10m〜90d")
	}

	if len(c.Challenge.Types) == 0 {
		c.Challenge.Types = []string{ChallengeHTTP01, ChallengeTLSALPN01}
	}
	for i, t := range c.Challenge.Types {
		if t != ChallengeHTTP01 && t != ChallengeTLSALPN01 {
			return fmt.Errorf("challenge.types: 未対応の %q（%s / %s）", t, ChallengeHTTP01, ChallengeTLSALPN01)
		}
		// 重複は意図しない設定なので、黙って除かずにエラーにする（提示順に意味があるのでソートもしない）。
		if slices.Contains(c.Challenge.Types[:i], t) {
			return fmt.Errorf("challenge.types: %q が重複している", t)
		}
	}
	if c.Challenge.HTTP01Port == 0 {
		c.Challenge.HTTP01Port = 80
	}
	if c.Challenge.TLSALPN01Port == 0 {
		c.Challenge.TLSALPN01Port = 443
	}
	for _, p := range []int{c.Challenge.HTTP01Port, c.Challenge.TLSALPN01Port} {
		if p < 1 || p > 65535 {
			return errors.New("challenge のポートは 1〜65535")
		}
	}
	if c.Challenge.Timeout == 0 {
		c.Challenge.Timeout = Duration(10 * time.Second)
	}
	if c.Challenge.Attempts == 0 {
		c.Challenge.Attempts = 3
	}
	if c.Challenge.Attempts < 1 || c.Challenge.Attempts > 10 {
		return errors.New("challenge.attempts は 1〜10")
	}
	if c.CRL.Validity == 0 {
		c.CRL.Validity = Duration(24 * time.Hour)
	}
	if err := c.Admin.complete(); err != nil {
		return err
	}
	return c.Log.complete()
}

// AllowedPrefixes は解釈済みの送信元制限を返す。
func (c *CA) AllowedPrefixes() []netip.Prefix { return c.allowedPrefixes }

func (l *Log) complete() error {
	if l.Level == "" {
		l.Level = "info"
	}
	if l.Format == "" {
		l.Format = "text"
	}
	switch l.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level: 未対応の %q", l.Level)
	}
	if l.Format != "text" && l.Format != "json" {
		return fmt.Errorf("log.format: 未対応の %q", l.Format)
	}
	return nil
}

func (a *CAAdmin) complete() error {
	if a.Listen == "" {
		return nil
	}
	if len(a.AllowedClients) == 0 {
		return errors.New("admin.allowed_clients は必須（管理画面に入れる管理者の証明書の名前を指定する）")
	}
	for i, p := range a.AllowedClients {
		p = names.Normalize(p)
		if err := names.ValidatePattern(p); err != nil {
			return fmt.Errorf("admin.allowed_clients: %w", err)
		}
		a.AllowedClients[i] = p
	}
	var err error
	if a.allowedPrefixes, err = parsePrefixes("admin.allowed_cidrs", a.AllowedCIDRs); err != nil {
		return err
	}
	if a.LogBuffer == 0 {
		a.LogBuffer = 5000
	}
	if a.LogBuffer < 100 || a.LogBuffer > 100000 {
		return errors.New("admin.log_buffer は 100〜100000")
	}
	return nil
}

// parsePrefixes は CIDR または IP アドレスの一覧を解釈する。
func parsePrefixes(key string, list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("%s: %q を解釈できない", key, s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
