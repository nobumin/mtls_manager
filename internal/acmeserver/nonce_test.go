package acmeserver

import (
	"testing"
	"time"
)

func TestNonceSingleUse(t *testing.T) {
	s := newNonceStoreSize(time.Minute, 4)
	n := s.issue()
	if !s.consume(n) {
		t.Fatal("発行した nonce が使えない")
	}
	if s.consume(n) {
		t.Fatal("同じ nonce を 2 回使えた")
	}
	if s.consume("unknown") {
		t.Fatal("発行していない nonce が使えた")
	}
}

// 上限に達したら、最も古いものから捨てる（直前に渡したものは捨てない）。
func TestNonceEvictsOldestFirst(t *testing.T) {
	s := newNonceStoreSize(time.Minute, 3)
	first := s.issue()
	second := s.issue()
	_ = s.issue()
	latest := s.issue() // first が捨てられる
	if s.consume(first) {
		t.Error("最も古い nonce が残っている")
	}
	if !s.consume(second) || !s.consume(latest) {
		t.Error("新しい nonce が捨てられた")
	}
	if len(s.nonces) != 1 {
		t.Errorf("map の件数 = %d、want 1", len(s.nonces))
	}
}

func TestNonceExpires(t *testing.T) {
	s := newNonceStoreSize(time.Millisecond, 4)
	n := s.issue()
	time.Sleep(5 * time.Millisecond)
	if s.consume(n) {
		t.Fatal("期限切れの nonce が使えた")
	}
}
