// Package agent は mtls-agent の本体。ACME で証明書を取得し、期限の前に自動で更新する。
package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/nobumin/mtls_manager/internal/config"
	"github.com/nobumin/mtls_manager/internal/names"
	"github.com/nobumin/mtls_manager/internal/pki"
	"github.com/nobumin/mtls_manager/internal/version"
)

// EnvEABHMAC は EAB の HMAC 鍵を渡す環境変数（hmac_file の代わり）。
const EnvEABHMAC = "MTLS_AGENT_EAB_HMAC"

// Agent は証明書の取得・更新を行う。
type Agent struct {
	cfg *config.Agent
	log *slog.Logger
	// roots は信頼するルート CA。ルート CA の入れ替え中は新旧の 2 枚を並べる。
	roots []*x509.Certificate
	pool  *x509.CertPool
	http  *http.Client

	mu     sync.Mutex
	client *acme.Client
}

// New は Agent を作る。
func New(cfg *config.Agent, log *slog.Logger) (*Agent, error) {
	roots, err := pki.LoadCerts(cfg.CARoot)
	if err != nil {
		return nil, fmt.Errorf("ca_root: %w", err)
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		if !r.IsCA {
			return nil, fmt.Errorf("ca_root: %s に CA ではない証明書（%s）が含まれる", cfg.CARoot, r.Subject)
		}
		pool.AddCert(r)
	}
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// 社内の CA へ直接つなぐ（環境変数のプロキシを経由しない）。
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	return &Agent{cfg: cfg, log: log, roots: roots, pool: pool, http: hc}, nil
}

// Status は現在の証明書の状態。
type Status struct {
	Exists   bool
	Names    []string
	Serial   string
	NotAfter time.Time
	RenewAt  time.Time
	// Reason は更新が必要な理由。空なら更新不要。
	Reason string
}

// NeedsRenewal は更新が必要かを返す。
func (s Status) NeedsRenewal() bool { return s.Reason != "" }

// Check は出力済みの証明書を調べ、更新が必要かを判断する。
func (a *Agent) Check(now time.Time) Status {
	certs, err := pki.LoadCerts(a.cfg.Output.Cert)
	if err != nil {
		return Status{Reason: "証明書が無い、または読めない"}
	}
	leaf := certs[0]
	saved := a.loadState()
	st := Status{
		Exists: true, Names: leaf.DNSNames, Serial: serialHex(leaf), NotAfter: leaf.NotAfter,
		RenewAt: renewAt(leaf, saved, a.cfg.Renew.Fraction),
	}
	key, err := pki.LoadPrivateKey(a.cfg.Output.Key)
	if err != nil && a.cfg.Output.KeyFileMode() != 0o600 {
		// 0640 の鍵は CheckPrivateFile を通らないので、権限を問わずに読む。
		key, err = loadKeyAnyMode(a.cfg.Output.Key)
	}
	switch {
	case err != nil:
		st.Reason = "秘密鍵が無い、または読めない"
	case !pki.PublicKeyEqual(leaf.PublicKey, key.Public()):
		st.Reason = "証明書と秘密鍵が対応していない"
	case !slices.Equal(normalized(leaf.DNSNames), a.cfg.Names):
		st.Reason = fmt.Sprintf("名前が設定と違う（証明書 %v、設定 %v）", leaf.DNSNames, a.cfg.Names)
	case a.verifyChain(leaf, a.intermediates(saved)) != nil:
		st.Reason = "ルート CA につながらない（CA が変わった可能性）"
	case !now.Before(leaf.NotAfter):
		st.Reason = "有効期限が切れている"
	case !now.Before(st.RenewAt):
		st.Reason = "更新時期を過ぎた"
	}
	return st
}

func loadKeyAnyMode(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pki.ParsePrivateKeyPEM(data)
}

func normalized(list []string) []string {
	out := make([]string, 0, len(list))
	for _, n := range list {
		out = append(out, names.Normalize(n))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// intermediates はチェーンの検証に使う中間 CA を集める。内部状態（<account_key>.state.json）に保存したものを必ず含めるので、
// chain / fullchain を出力しない設定でも検証できる（出力済みのファイルにあるものも加える）。
func (a *Agent) intermediates(saved *state) []*x509.Certificate {
	var out []*x509.Certificate
	if saved != nil && saved.IntermediatesPEM != "" {
		if c, err := pki.ParseCertsPEM([]byte(saved.IntermediatesPEM)); err == nil {
			out = append(out, c...)
		}
	}
	if a.cfg.Output.Chain != "" {
		if c, err := pki.LoadCerts(a.cfg.Output.Chain); err == nil {
			out = append(out, c...)
		}
	}
	if a.cfg.Output.Fullchain != "" {
		if c, err := pki.LoadCerts(a.cfg.Output.Fullchain); err == nil && len(c) > 1 {
			out = append(out, c[1:]...)
		}
	}
	return out
}

// renewAt は更新時期を返す。取得した時刻が分かれば、そこから有効期間の fraction を数える
// （CA は NotBefore を過去にずらすので、NotBefore から数えると、有効期間が短いときに発行直後から更新時期を過ぎてしまう）。
func renewAt(leaf *x509.Certificate, saved *state, fraction float64) time.Time {
	start := leaf.NotBefore
	if saved != nil && saved.Serial == serialHex(leaf) && saved.ObtainedAt.After(start) && saved.ObtainedAt.Before(leaf.NotAfter) {
		start = saved.ObtainedAt
	}
	return start.Add(time.Duration(float64(leaf.NotAfter.Sub(start)) * fraction))
}

func serialHex(c *x509.Certificate) string { return fmt.Sprintf("%x", c.SerialNumber) }

func (a *Agent) verifyChain(leaf *x509.Certificate, inters []*x509.Certificate) error {
	ipool := x509.NewCertPool()
	for _, c := range inters {
		ipool.AddCert(c)
	}
	for _, ku := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: a.pool, Intermediates: ipool, KeyUsages: []x509.ExtKeyUsage{ku}, CurrentTime: leaf.NotBefore.Add(time.Minute)}); err != nil {
			return err
		}
	}
	return nil
}

// acmeClient はアカウントを用意した ACME クライアントを返す（初回はアカウント鍵の作成と EAB での登録）。
func (a *Agent) acmeClient(ctx context.Context) (*acme.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil {
		return a.client, nil
	}
	key, err := a.accountKey()
	if err != nil {
		return nil, err
	}
	c := &acme.Client{Key: key, DirectoryURL: a.cfg.CAURL, HTTPClient: a.http, UserAgent: "mtls-agent/" + version.Version}
	_, err = c.GetReg(ctx, "")
	if errors.Is(err, acme.ErrNoAccount) {
		hmacKey, herr := a.eabHMAC()
		if herr != nil {
			return nil, herr
		}
		_, err = c.Register(ctx, &acme.Account{ExternalAccountBinding: &acme.ExternalAccountBinding{KID: a.cfg.EAB.KID, Key: hmacKey}}, acme.AcceptTOS)
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			err = nil
		}
		if err == nil {
			a.log.Info("CA にアカウントを登録した", "eab_kid", a.cfg.EAB.KID)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("アカウントを用意できない: %w", err)
	}
	a.client = c
	return c, nil
}

func (a *Agent) accountKey() (crypto.Signer, error) {
	key, err := pki.LoadPrivateKey(a.cfg.AccountKey)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("account_key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(a.cfg.AccountKey), 0o700); err != nil {
		return nil, err
	}
	key, err = pki.GenerateKey(pki.KeyECDSAP256)
	if err != nil {
		return nil, err
	}
	if err := pki.SavePrivateKey(a.cfg.AccountKey, key); err != nil {
		return nil, fmt.Errorf("account_key: %w", err)
	}
	a.log.Info("アカウント鍵を作成した", "path", a.cfg.AccountKey)
	return key, nil
}

func (a *Agent) eabHMAC() ([]byte, error) {
	if a.cfg.EAB.KID == "" {
		return nil, errors.New("初回の登録には eab.kid が必要（mtlsctl eab create で発行する）")
	}
	raw := os.Getenv(EnvEABHMAC)
	if raw == "" {
		if a.cfg.EAB.HMACFile == "" {
			return nil, fmt.Errorf("初回の登録には eab.hmac_file か環境変数 %s が必要", EnvEABHMAC)
		}
		data, err := pki.ReadPrivateFile(a.cfg.EAB.HMACFile)
		if err != nil {
			return nil, fmt.Errorf("eab.hmac_file: %w", err)
		}
		raw = string(data)
	}
	raw = strings.TrimSpace(raw)
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
	if err != nil {
		return nil, errors.New("EAB の HMAC 鍵を base64url として解釈できない")
	}
	return key, nil
}

// Obtain は証明書を取得してファイルに書き、更新後のコマンドを実行する。
func (a *Agent) Obtain(ctx context.Context) (err error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Renew.Timeout.D())
	defer cancel()
	defer func() {
		if needsReregistration(err) {
			// CA 側でアカウントが失われた（データベースを古いバックアップから戻した等）。
			// 使い回しのクライアントを捨て、次の試行で EAB による再登録からやり直す。
			a.log.Warn("CA がアカウントを受け付けない。次の試行でアカウントを確認し直す", "err", err)
			a.mu.Lock()
			a.client = nil
			a.mu.Unlock()
		}
	}()
	c, err := a.acmeClient(ctx)
	if err != nil {
		return err
	}
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(a.cfg.Names...))
	if err != nil {
		return fmt.Errorf("注文できない: %w", err)
	}

	resp, err := newResponder(a.cfg.Challenge, c)
	if err != nil {
		return err
	}
	defer resp.close()
	var pending []string
	for _, u := range order.AuthzURLs {
		z, err := c.GetAuthorization(ctx, u)
		if err != nil {
			return err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, ch := range z.Challenges {
			if ch.Type == a.cfg.Challenge.Type {
				chal = ch
			}
		}
		if chal == nil {
			return fmt.Errorf("CA が %s のチャレンジを提示しなかった", a.cfg.Challenge.Type)
		}
		if err := resp.add(chal.Token, z.Identifier.Value); err != nil {
			return err
		}
		if _, err := c.Accept(ctx, chal); err != nil {
			return fmt.Errorf("チャレンジを開始できない: %w", err)
		}
		pending = append(pending, u)
	}
	for _, u := range pending {
		if _, err := c.WaitAuthorization(ctx, u); err != nil {
			return fmt.Errorf("所有確認に失敗した: %w", err)
		}
	}
	resp.close()

	key, err := pki.GenerateKey(a.cfg.KeyType)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: a.cfg.Names}, key)
	if err != nil {
		return err
	}
	ders, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("発行に失敗した: %w", err)
	}
	chain := make([]*x509.Certificate, 0, len(ders))
	for _, d := range ders {
		cert, err := x509.ParseCertificate(d)
		if err != nil {
			return fmt.Errorf("発行された証明書を解釈できない: %w", err)
		}
		chain = append(chain, cert)
	}
	if err := a.checkIssued(chain, key); err != nil {
		return fmt.Errorf("発行された証明書が想定と違う: %w", err)
	}
	// 内部状態を先に保存する（失敗したら出力を書き換えずにやり直す）。
	if err := a.saveState(chain[0], chain[1:], time.Now()); err != nil {
		return fmt.Errorf("内部状態を保存できない: %w", err)
	}
	if err := a.write(chain, key); err != nil {
		return fmt.Errorf("証明書を書き出せない: %w", err)
	}
	a.log.Info("証明書を更新した", "names", a.cfg.Names, "serial", serialHex(chain[0]), "not_after", chain[0].NotAfter)
	a.runHook(ctx)
	return nil
}

func (a *Agent) checkIssued(chain []*x509.Certificate, key crypto.Signer) error {
	if len(chain) == 0 {
		return errors.New("証明書が空")
	}
	leaf := chain[0]
	if !pki.PublicKeyEqual(leaf.PublicKey, key.Public()) {
		return errors.New("公開鍵が一致しない")
	}
	if !slices.Equal(normalized(leaf.DNSNames), a.cfg.Names) {
		return fmt.Errorf("名前が一致しない（%v）", leaf.DNSNames)
	}
	return a.verifyChain(leaf, chain[1:])
}

// write は鍵 → 証明書の順にアトミックに書く。アプリ側（mtls ライブラリ）は対応しない組を読んでも
// 直前の証明書を使い続けるので、途中の状態で接続が切れることはない。
func (a *Agent) write(chain []*x509.Certificate, key crypto.Signer) error {
	o := a.cfg.Output
	keyPEM, err := pki.MarshalPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	type out struct {
		path string
		data []byte
		perm fs.FileMode
	}
	outs := []out{
		{o.Key, keyPEM, o.KeyFileMode()},
		{o.CA, pki.EncodeCertsPEM(a.roots...), 0o644},
		{o.Chain, pki.EncodeCertsPEM(chain[1:]...), 0o644},
		{o.Fullchain, pki.EncodeCertsPEM(chain...), 0o644},
		// cert は最後に書く（更新の検知に使えるようにする。deploy/systemd/mtls-reload-nginx.path）
		{o.Cert, pki.EncodeCertsPEM(chain[0]), 0o644},
	}
	for _, f := range outs {
		if f.path == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			return err
		}
		if err := pki.WriteFileAtomic(f.path, f.data, f.perm); err != nil {
			return err
		}
	}
	return nil
}

// runHook は更新後のコマンドを実行する。失敗しても証明書の更新は取り消さない（ログに残す）。
func (a *Agent) runHook(ctx context.Context) {
	argv := a.cfg.Hooks.PostRenew
	if len(argv) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.Hooks.Timeout.D())
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(),
		"MTLS_AGENT_NAMES="+strings.Join(a.cfg.Names, ","),
		"MTLS_AGENT_CERT="+a.cfg.Output.Cert,
		"MTLS_AGENT_KEY="+a.cfg.Output.Key,
		"MTLS_AGENT_FULLCHAIN="+a.cfg.Output.Fullchain,
	)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		a.log.Error("更新後のコマンドが失敗した", "command", argv, "err", err, "output", truncate(buf.String(), 2000))
		return
	}
	a.log.Info("更新後のコマンドを実行した", "command", argv)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// 再試行の待ち時間（指数バックオフ）。
const (
	minBackoff = 30 * time.Second
	maxBackoff = 15 * time.Minute
)

// backoff は待ち時間を倍にしていく（min から始めて max で止める）。
type backoff struct {
	min, max, cur time.Duration
}

// next は次の待ち時間を返す。呼ぶたびに倍になる。
func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = b.min
	} else {
		b.cur = min(b.cur*2, b.max)
	}
	return b.cur
}

// reset は待ち時間を最初に戻す。
func (b *backoff) reset() { b.cur = 0 }

// Run は ctx が終わるまで、状態の確認と更新を繰り返す。renewNow に値が届くと、時期を問わず更新する。
func (a *Agent) Run(ctx context.Context, renewNow <-chan struct{}) {
	// failure は取得に失敗したとき、safety は取得した直後なのに更新が必要と判断されたとき（安全弁）の待ち時間。
	// 安全弁が続けて働くたびに待ち時間を伸ばし、同種の不具合で再発行を繰り返さないようにする。
	failure := &backoff{min: minBackoff, max: maxBackoff}
	safety := &backoff{min: minBackoff, max: maxBackoff}
	force := false
	for {
		st := a.Check(time.Now())
		var wait time.Duration
		if st.NeedsRenewal() || force {
			reason := st.Reason
			if force {
				reason = "手動での更新要求"
			}
			a.log.Info("証明書を取得する", "reason", reason)
			if err := a.Obtain(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				wait = jitter(failure.next())
				a.log.Error("証明書を取得できない（再試行する）", "err", err, "retry_in", wait.Round(time.Second))
			} else {
				force = false
				failure.reset()
				if after := a.Check(time.Now()); after.NeedsRenewal() {
					wait = jitter(max(a.cfg.Renew.CheckInterval.D(), safety.next()))
					a.log.Warn("取得した直後なのに更新が必要と判断された。設定と CA の状態を確認すること",
						"reason", after.Reason, "retry_in", wait)
				} else {
					safety.reset()
					continue
				}
			}
		} else {
			safety.reset()
			wait = min(a.cfg.Renew.CheckInterval.D(), time.Until(st.RenewAt))
			a.log.Debug("更新は不要", "renew_at", st.RenewAt, "not_after", st.NotAfter)
		}
		t := time.NewTimer(max(wait, time.Second))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-renewNow:
			t.Stop()
			force = true
		case <-t.C:
		}
	}
}

// jitter は ±20% の揺らぎを加える（多数のホストの再試行が同時に集中しないようにする）。
func jitter(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)*2/5+1))
	if err != nil {
		return d
	}
	return d - d/5 + time.Duration(n.Int64())
}

// needsReregistration は、アカウントを確認し直すべきエラー（CA がアカウントを知らない・受け付けない）かを返す。
func needsReregistration(err error) bool {
	var ae *acme.Error
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.ProblemType {
	case "urn:ietf:params:acme:error:accountDoesNotExist", "urn:ietf:params:acme:error:unauthorized":
		return true
	}
	return false
}
