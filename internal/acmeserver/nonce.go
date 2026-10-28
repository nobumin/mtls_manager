package acmeserver

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// nonceStore は Replay-Nonce を 1 回限り有効にする（リプレイ攻撃の防止）。
// メモリ上に持つので CA を再起動すると無効になるが、クライアントは badNonce を受けて取り直す。
type nonceStore struct {
	ttl time.Duration
	max int

	mu     sync.Mutex
	nonces map[string]time.Time
}

func newNonceStore() *nonceStore {
	return &nonceStore{ttl: time.Hour, max: 100000, nonces: map[string]time.Time{}}
}

func (s *nonceStore) issue() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand は失敗しない
	}
	n := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.nonces) >= s.max {
		for k, exp := range s.nonces {
			if now.After(exp) {
				delete(s.nonces, k)
			}
		}
		// それでも溢れる場合は任意の古いものを捨てる（捨てられた側は badNonce で取り直す）。
		for k := range s.nonces {
			if len(s.nonces) < s.max {
				break
			}
			delete(s.nonces, k)
		}
	}
	s.nonces[n] = now.Add(s.ttl)
	return n
}

// consume は nonce が有効なら消費して true を返す。
func (s *nonceStore) consume(n string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.nonces[n]
	if !ok {
		return false
	}
	delete(s.nonces, n)
	return time.Now().Before(exp)
}
