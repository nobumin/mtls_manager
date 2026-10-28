package acmeserver

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/nobumin/mtls_manager/internal/pki"
)

// SelfCert は CA 自身の TLS サーバ証明書を中間 CA で発行し、期限の前に作り直す。
// クライアントはルート CA だけを信頼すれば CA に接続できる（別途サーバ証明書を用意しなくてよい）。
type SelfCert struct {
	issuer   *pki.Issuer
	names    []string
	validity time.Duration

	mu      sync.Mutex
	cur     *tls.Certificate
	renewAt time.Time
}

// NewSelfCert は最初の証明書を発行して SelfCert を作る。
func NewSelfCert(iss *pki.Issuer, names []string, validity time.Duration) (*SelfCert, error) {
	for _, n := range names {
		if !iss.Permits(n) {
			return nil, fmt.Errorf("CA のホスト名 %q が中間 CA の名前制約 %v の範囲外", n, iss.Cert.PermittedDNSDomains)
		}
	}
	s := &SelfCert{issuer: iss, names: names, validity: validity}
	if err := s.renewLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SelfCert) renewLocked() error {
	key, err := pki.GenerateKey(pki.KeyECDSAP256)
	if err != nil {
		return err
	}
	leaf, err := s.issuer.IssueLeaf(key.Public(), s.names, s.validity)
	if err != nil {
		return err
	}
	s.cur = &tls.Certificate{Certificate: [][]byte{leaf.Raw, s.issuer.Cert.Raw}, PrivateKey: key, Leaf: leaf}
	s.renewAt = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
	return nil
}

// GetCertificate は tls.Config.GetCertificate に設定する。
func (s *SelfCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().After(s.renewAt) {
		if err := s.renewLocked(); err != nil {
			// 作り直せなくても、期限内なら現在の証明書を使い続ける。
			if time.Now().After(s.cur.Leaf.NotAfter) {
				return nil, err
			}
		}
	}
	return s.cur, nil
}
