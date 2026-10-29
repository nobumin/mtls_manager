package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nobumin/mtls_manager/internal/federation"
)

// 連携版（設計 9-1）: 自分のルート CA（CAFile）に加えて、トラストバンドル（TrustBundleFile）の連携先のルート CA を、
// その範囲の名前に限って信頼する。
//   - 自分のルート CA と自分の範囲は、バンドルからは取らない（CAFile と、自分の中間 CA の名前制約から得る）
//   - バンドルは再起動なしで読み直す。署名・自分のルートの指紋・範囲の重なりを確かめ、満たさなければ使わない
//   - バンドルの有効期限が切れたら、連携先のルートだけを外す（自分のルートは信頼し続ける）
//   - 連携先のルートにつながる証明書は、DNS 名が 1 つ以上・ワイルドカードなし・DNS 名以外の SAN なし・範囲の内に限る

// trustStore は自分のルート CA と、検証を通った連携先を持つ。
type trustStore struct {
	ownRoots   []*x509.Certificate
	ownPool    *x509.CertPool
	bundleFile string
	ownDomains []string
	src        *Source
	interval   time.Duration
	log        *slog.Logger

	mu        sync.Mutex
	lastCheck time.Time
	accepted  *federation.Verified
	lastErr   string
	expired   bool
}

func newTrustStore(c Config, src *Source) (*trustStore, error) {
	data, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, err
	}
	roots, err := parseCerts(data)
	if err != nil {
		return nil, fmt.Errorf("mtls: %s: %w", c.CAFile, err)
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	t := &trustStore{ownRoots: roots, ownPool: pool, bundleFile: c.TrustBundleFile, ownDomains: c.OwnDomains, src: src, interval: c.ReloadInterval, log: c.Logger}
	t.reload(time.Now())
	return t, nil
}

func parseCerts(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		c, rest, err := nextCert(data)
		if err != nil {
			return nil, err
		}
		if c == nil {
			break
		}
		out, data = append(out, c), rest
	}
	if len(out) == 0 {
		return nil, errors.New("証明書が無い")
	}
	return out, nil
}

// partners は、いま信頼してよい連携先を返す。間隔が過ぎていればバンドルを読み直す。
func (t *trustStore) partners(now time.Time) []federation.TrustedPartner {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.lastCheck) >= t.interval {
		t.reloadLocked(now)
	}
	if t.accepted == nil {
		return nil
	}
	if !now.Before(t.accepted.Bundle.Expires) {
		if !t.expired {
			t.log.Error("mtls: トラストバンドルの有効期限が切れた。連携先のルート CA を外す（自分のルート CA は信頼し続ける）", "expires", t.accepted.Bundle.Expires)
			t.expired = true
		}
		return nil
	}
	return t.accepted.Partners
}

func (t *trustStore) reload(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reloadLocked(now)
}

func (t *trustStore) reloadLocked(now time.Time) {
	t.lastCheck = now
	v, err := t.load(now)
	switch {
	case err == nil:
		if t.accepted == nil || v.Bundle.Epoch != t.accepted.Bundle.Epoch || v.Bundle.Seq != t.accepted.Bundle.Seq {
			for _, d := range v.Dropped {
				t.log.Error("mtls: トラストバンドルの連携先を外した", "reason", d)
			}
			ids := make([]string, 0, len(v.Partners))
			for _, p := range v.Partners {
				ids = append(ids, p.ID)
			}
			t.log.Info("mtls: トラストバンドルを読み込んだ", "seq", v.Bundle.Seq, "partners", ids, "expires", v.Bundle.Expires)
		}
		t.accepted, t.lastErr, t.expired = v, "", false
	case errors.Is(err, federation.ErrBundleExpired):
		t.accepted = nil
		if err.Error() != t.lastErr {
			t.log.Error("mtls: トラストバンドルの有効期限が切れている。連携先のルート CA を信頼しない（mtls-agent を確認する）")
			t.lastErr = err.Error()
		}
	default:
		// 不正なバンドルは使わず、直前に受け入れたものを有効期限まで使う。
		if err.Error() != t.lastErr {
			t.log.Error("mtls: トラストバンドルを使えない（直前のものを有効期限まで使う）", "err", err)
			t.lastErr = err.Error()
		}
	}
}

func (t *trustStore) load(now time.Time) (*federation.Verified, error) {
	data, err := os.ReadFile(t.bundleFile)
	if err != nil {
		return nil, err
	}
	inter, err := t.ownIntermediate()
	if err != nil {
		return nil, err
	}
	scope, err := federation.OwnScope(inter, t.ownPool, t.ownDomains)
	if err != nil {
		return nil, err
	}
	return federation.Verify(strings.TrimSpace(string(data)), federation.VerifyOptions{
		OwnRoots: t.ownRoots, OwnScope: scope, SignerConstraints: inter.PermittedDNSDomains, Now: now,
	})
}

// ownIntermediate は自分の証明書（fullchain）から、自分の証明書を発行した中間 CA を得る。
func (t *trustStore) ownIntermediate() (*x509.Certificate, error) {
	cert := t.src.Certificate()
	if len(cert.Certificate) < 2 {
		return nil, errors.New("CertFile に中間 CA が無い（連携版では fullchain を指定する）")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	for _, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err == nil && leaf.CheckSignatureFrom(c) == nil {
			return c, nil
		}
	}
	return nil, errors.New("自分の証明書を発行した中間 CA が CertFile に無い")
}

// verifyConnection は、自分のルート CA または連携先のルート CA（範囲の内に限る）につながることを確かめる。
// server が true ならクライアント証明書を、false ならサーバ証明書（ホスト名も）を確かめる。
func (t *trustStore) verifyConnection(server bool, allowed []string) func(tls.ConnectionState) error {
	allowed = slices.Clone(allowed)
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("mtls: 相手が証明書を提示しなかった")
		}
		leaf := cs.PeerCertificates[0]
		inters := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inters.AddCert(c)
		}
		partners := t.partners(time.Now())
		roots := t.ownPool.Clone()
		for _, p := range partners {
			roots.AddCert(p.Root)
		}
		opts := x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if !server {
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			opts.DNSName = cs.ServerName
		}
		chains, err := leaf.Verify(opts)
		if err != nil {
			return fmt.Errorf("mtls: 相手の証明書を検証できない: %w", err)
		}
		var reasons []string
		accepted := false
		for _, chain := range chains {
			root := chain[len(chain)-1]
			if slices.ContainsFunc(t.ownRoots, root.Equal) {
				accepted = true
				break
			}
			for _, p := range partners {
				if !p.Root.Equal(root) {
					continue
				}
				if err := federation.CheckPeer(leaf, p.Domains); err != nil {
					reasons = append(reasons, fmt.Sprintf("連携先 %s: %v", p.ID, err))
					continue
				}
				accepted = true
			}
			if accepted {
				break
			}
		}
		if !accepted {
			if len(reasons) == 0 {
				reasons = append(reasons, "信頼するルート CA につながらない")
			}
			return fmt.Errorf("mtls: 相手 %v を受け入れない（%s）", leaf.DNSNames, strings.Join(reasons, "、"))
		}
		if len(allowed) > 0 {
			return VerifyPeer(allowed)(cs)
		}
		return nil
	}
}

// nextCert は PEM の次の証明書を返す（無ければ nil）。
func nextCert(data []byte) (*x509.Certificate, []byte, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, nil, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return c, data, nil
	}
}
