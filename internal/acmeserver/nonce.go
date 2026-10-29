package acmeserver

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// nonceStore は Replay-Nonce を 1 回限り有効にする（リプレイ攻撃の防止）。
// メモリ上に持つので CA を再起動すると無効になるが、クライアントは badNonce を受けて取り直す。
//
// 発行順のリングバッファで持ち、上限に達したら最も古いものから捨てる（発行・消費とも O(1)）。
// ACME のクライアントは nonce を受け取ってすぐ使うので、有効期間は短くてよい。
type nonceStore struct {
	ttl time.Duration

	mu     sync.Mutex
	nonces map[string]time.Time // nonce → 期限
	ring   []string             // 発行順。next の位置が最も古い
	next   int
}

func newNonceStore() *nonceStore {
	return newNonceStoreSize(5*time.Minute, 100000)
}

func newNonceStoreSize(ttl time.Duration, max int) *nonceStore {
	return &nonceStore{ttl: ttl, nonces: make(map[string]time.Time, max), ring: make([]string, max)}
}

func (s *nonceStore) issue() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand は失敗しない
	}
	n := base64.RawURLEncoding.EncodeToString(b)
	exp := time.Now().Add(s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	// 最も古い枠を上書きする。その nonce がまだ使われていなければ、ここで無効になる。
	if old := s.ring[s.next]; old != "" {
		delete(s.nonces, old)
	}
	s.ring[s.next] = n
	s.next = (s.next + 1) % len(s.ring)
	s.nonces[n] = exp
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
	// リングの枠は上書きされるまで残るが、map から消えていれば無効として扱われる。
	delete(s.nonces, n)
	return time.Now().Before(exp)
}
