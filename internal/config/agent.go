package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"slices"
	"time"

	"github.com/nobumin/mtls_manager/internal/names"
	"github.com/nobumin/mtls_manager/internal/pki"
)

// Agent は mtls-agent の設定。
type Agent struct {
	// CAURL は ACME のディレクトリ URL（例: https://ca.internal.example.com:8443/acme/directory）。
	CAURL string `yaml:"ca_url"`
	// CARoot はルート CA の証明書。CA への接続の検証と、発行された証明書の検証に使う。
	// ルート CA の入れ替え中は、新旧の証明書を 1 つのファイルに並べてよい。
	CARoot string `yaml:"ca_root"`
	// AccountKey は ACME アカウントの鍵。無ければ初回に作る（0600）。
	AccountKey string `yaml:"account_key"`

	EAB AgentEAB `yaml:"eab"`

	// Names は証明書に載せる名前（FQDN）。
	Names []string `yaml:"names"`
	// KeyType は証明書の鍵の種類。既定 ecdsa-p256。
	KeyType string `yaml:"key_type"`

	Challenge AgentChallenge `yaml:"challenge"`
	Output    AgentOutput    `yaml:"output"`
	Renew     AgentRenew     `yaml:"renew"`
	Hooks     AgentHooks     `yaml:"hooks"`
	Log       Log            `yaml:"log"`
}

// AgentEAB は初回のアカウント登録に使う External Account Binding。
type AgentEAB struct {
	// KID は mtlsctl eab create が表示する鍵 ID。
	KID string `yaml:"kid"`
	// HMACFile は HMAC 鍵（base64url）のファイル（0600）。環境変数 MTLS_AGENT_EAB_HMAC でも渡せる。
	HMACFile string `yaml:"hmac_file"`
}

// AgentChallenge は所有確認への応答方法。
type AgentChallenge struct {
	// Type は http-01 / tls-alpn-01。既定 http-01。
	Type string `yaml:"type"`
	// Listen は応答用に一時的に開くアドレス。既定 http-01 は ":80"、tls-alpn-01 は ":443"。
	Listen string `yaml:"listen"`
	// Webroot を指定すると、http-01 で待ち受けず、既存の Web サーバの公開ディレクトリに応答ファイルを置く。
	Webroot string `yaml:"webroot"`
}

// AgentOutput は証明書・鍵の出力先。
type AgentOutput struct {
	Cert      string `yaml:"cert"`      // 末端の証明書のみ
	Chain     string `yaml:"chain"`     // 中間 CA の証明書（任意）
	Fullchain string `yaml:"fullchain"` // 末端 + 中間 CA（任意）
	Key       string `yaml:"key"`       // 秘密鍵
	CA        string `yaml:"ca"`        // ルート CA の写し（任意。アプリの信頼先に使う）
	// KeyMode は秘密鍵の権限。0600（既定）または 0640（同じグループのアプリに読ませる場合）。
	KeyMode string `yaml:"key_mode"`

	keyMode fs.FileMode
}

// AgentRenew は更新の条件。
type AgentRenew struct {
	// Fraction は有効期間のうち、この割合が過ぎたら更新する。既定 0.66（残り 1/3 で更新）。
	Fraction float64 `yaml:"fraction"`
	// CheckInterval は状態を確かめる間隔。既定 1m。
	CheckInterval Duration `yaml:"check_interval"`
	// Timeout は 1 回の取得の制限時間。既定 5m。
	Timeout Duration `yaml:"timeout"`
}

// AgentHooks は更新後に実行するコマンド。
type AgentHooks struct {
	// PostRenew は更新後に実行するコマンド（シェルを介さず実行する。例: ["systemctl", "reload", "nginx"]）。
	PostRenew []string `yaml:"post_renew"`
	// Timeout は既定 60s。
	Timeout Duration `yaml:"timeout"`
}

// LoadAgent は設定を読み、既定値を補って検証する。
func LoadAgent(path string) (*Agent, error) {
	a := &Agent{}
	if err := load(path, a); err != nil {
		return nil, err
	}
	if err := a.Complete(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return a, nil
}

// Complete は既定値を補って検証する。
func (a *Agent) Complete() error {
	u, err := url.Parse(a.CAURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("ca_url は https:// で始まる ACME ディレクトリの URL にする")
	}
	for _, f := range []struct{ name, v string }{
		{"ca_root", a.CARoot}, {"account_key", a.AccountKey}, {"output.cert", a.Output.Cert}, {"output.key", a.Output.Key},
	} {
		if f.v == "" {
			return fmt.Errorf("%s は必須", f.name)
		}
	}
	if len(a.Names) == 0 {
		return errors.New("names は必須")
	}
	for i, n := range a.Names {
		n = names.Normalize(n)
		if err := names.ValidateHostname(n); err != nil {
			return fmt.Errorf("names: %w", err)
		}
		a.Names[i] = n
	}
	slices.Sort(a.Names)
	a.Names = slices.Compact(a.Names)
	if a.KeyType == "" {
		a.KeyType = pki.KeyECDSAP256
	}
	if !slices.Contains(pki.KeyTypes, a.KeyType) {
		return fmt.Errorf("key_type: 未対応の %q（%v）", a.KeyType, pki.KeyTypes)
	}

	switch a.Challenge.Type {
	case "":
		a.Challenge.Type = ChallengeHTTP01
	case ChallengeHTTP01, ChallengeTLSALPN01:
	default:
		return fmt.Errorf("challenge.type: 未対応の %q", a.Challenge.Type)
	}
	if a.Challenge.Webroot != "" && a.Challenge.Type != ChallengeHTTP01 {
		return errors.New("challenge.webroot は http-01 でのみ使える")
	}
	if a.Challenge.Listen == "" {
		if a.Challenge.Type == ChallengeHTTP01 {
			a.Challenge.Listen = ":80"
		} else {
			a.Challenge.Listen = ":443"
		}
	}

	switch a.Output.KeyMode {
	case "", "0600", "600":
		a.Output.keyMode = 0o600
	case "0640", "640":
		a.Output.keyMode = 0o640
	default:
		return fmt.Errorf("output.key_mode は 0600 か 0640（%q）", a.Output.KeyMode)
	}

	if a.Renew.Fraction == 0 {
		a.Renew.Fraction = 0.66
	}
	if a.Renew.Fraction < 0.1 || a.Renew.Fraction > 0.9 {
		return errors.New("renew.fraction は 0.1〜0.9")
	}
	if a.Renew.CheckInterval == 0 {
		a.Renew.CheckInterval = Duration(time.Minute)
	}
	if a.Renew.CheckInterval.D() < time.Second {
		return errors.New("renew.check_interval は 1s 以上")
	}
	if a.Renew.Timeout == 0 {
		a.Renew.Timeout = Duration(5 * time.Minute)
	}
	if a.Hooks.Timeout == 0 {
		a.Hooks.Timeout = Duration(60 * time.Second)
	}
	return a.Log.complete()
}

// KeyFileMode は秘密鍵の出力権限を返す。
func (o AgentOutput) KeyFileMode() fs.FileMode { return o.keyMode }
