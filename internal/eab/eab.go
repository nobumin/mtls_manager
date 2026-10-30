// Package eab は External Account Binding（EAB）の鍵ファイルを扱う。
//
// EAB 鍵は「このホストに証明書の発行を依頼させてよい」という事前の許可で、
// 鍵ごとに発行してよい名前（パターン）を結び付ける。鍵ファイルから削除すると、
// その鍵で登録したアカウントは以後、新しい証明書を取得できなくなる。
package eab

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nobumin/mtls_manager/internal/flock"
	"github.com/nobumin/mtls_manager/internal/names"
	"github.com/nobumin/mtls_manager/internal/pki"
)

// Key は 1 つの EAB 鍵。
type Key struct {
	KID string `json:"kid"`
	// HMAC は HMAC 鍵（base64url、パディングなし）。
	HMAC string `json:"hmac"`
	// Names はこの鍵で発行してよい名前のパターン（names パッケージの書式）。
	Names     []string  `json:"names"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// HMACKey は復号した HMAC 鍵を返す。
func (k Key) HMACKey() ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(k.HMAC)
	if err != nil {
		return nil, fmt.Errorf("EAB 鍵 %s の hmac が不正: %w", k.KID, err)
	}
	if len(b) < 32 {
		return nil, fmt.Errorf("EAB 鍵 %s の hmac が短すぎる", k.KID)
	}
	return b, nil
}

// Permits は name がこの鍵のパターンに一致するかを返す。
func (k Key) Permits(name string) bool { return names.MatchAny(k.Names, name) }

// File は鍵ファイルの中身。
type File struct {
	Keys []Key `json:"keys"`
}

// Load は鍵ファイルを読む（権限 0600 必須）。
func Load(path string) (*File, error) {
	data, err := pki.ReadPrivateFile(path)
	if err != nil {
		return nil, err
	}
	f := &File{}
	if err := json.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, k := range f.Keys {
		if k.KID == "" || seen[k.KID] {
			return nil, fmt.Errorf("%s: kid が空または重複している", path)
		}
		seen[k.KID] = true
		if _, err := k.HMACKey(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, p := range k.Names {
			if err := names.ValidatePattern(p); err != nil {
				return nil, fmt.Errorf("%s: kid %s: %w", path, k.KID, err)
			}
		}
	}
	return f, nil
}

// LoadOrEmpty はファイルが無ければ空の File を返す。
func LoadOrEmpty(path string) (*File, error) {
	f, err := Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &File{}, nil
	}
	return f, err
}

// Save は 0600 でアトミックに書く。
func (f *File) Save(path string) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return pki.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// Add は新しい鍵を作って追加し、その鍵を返す。
func (f *File) Add(patterns []string, note string) (Key, error) {
	if len(patterns) == 0 {
		return Key{}, errors.New("発行してよい名前（パターン）を 1 つ以上指定する")
	}
	norm := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = names.Normalize(p)
		if err := names.ValidatePattern(p); err != nil {
			return Key{}, err
		}
		norm = append(norm, p)
	}
	slices.Sort(norm)
	kid, err := randomString(16)
	if err != nil {
		return Key{}, err
	}
	hmacKey, err := randomString(32)
	if err != nil {
		return Key{}, err
	}
	k := Key{KID: kid, HMAC: hmacKey, Names: slices.Compact(norm), Note: note, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	f.Keys = append(f.Keys, k)
	return k, nil
}

// Remove は鍵を削除する。見つからなければ false。
func (f *File) Remove(kid string) bool {
	n := len(f.Keys)
	f.Keys = slices.DeleteFunc(f.Keys, func(k Key) bool { return k.KID == kid })
	return len(f.Keys) != n
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Store は CA が鍵ファイルを参照するためのもの。ファイルの更新（mtlsctl eab create / revoke）を
// 再起動なしで反映する。
type Store struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	keys    map[string]Key
}

// NewStore は鍵ファイルを読み込んで Store を作る。
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.reloadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// Lookup は kid の鍵を返す。ファイルが変わっていれば読み直す。
// 読み直しに失敗したときは安全側に倒し、エラーを返す（古い鍵で許可し続けない）。
func (s *Store) Lookup(kid string) (Key, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadLocked(); err != nil {
		return Key{}, false, err
	}
	k, ok := s.keys[kid]
	return k, ok, nil
}

func (s *Store) reloadLocked() error {
	fi, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	if s.keys != nil && fi.ModTime().Equal(s.modTime) && fi.Size() == s.size {
		return nil
	}
	f, err := Load(s.path)
	if err != nil {
		return err
	}
	keys := make(map[string]Key, len(f.Keys))
	for _, k := range f.Keys {
		keys[k.KID] = k
	}
	s.keys, s.modTime, s.size = keys, fi.ModTime(), fi.Size()
	return nil
}

// Update は鍵ファイルを排他ロックの下で読み、fn で変更して書き戻す（無ければ空から作る）。
// mtlsctl eab create / revoke を同時に実行しても、一方の変更（鍵の取り消しなど）が失われない。
func Update(path string, fn func(*File) error) error {
	unlock, err := flock.Lock(path)
	if err != nil {
		return fmt.Errorf("%s をロックできない: %w", path, err)
	}
	defer unlock()
	f, err := LoadOrEmpty(path)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	return f.Save(path)
}

// Keys は現在の鍵を作成日時の順に返す（管理画面用）。ファイルが変わっていれば読み直す。
func (s *Store) Keys() ([]Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadLocked(); err != nil {
		return nil, err
	}
	out := make([]Key, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b Key) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

// PermitsExactly は name をワイルドカードを使わずに（完全一致で）許可しているかを返す。
// 管理者の名前の証明書は、この条件を満たす鍵でだけ発行する（サーバ用のワイルドカードの鍵で取られないように）。
func (k Key) PermitsExactly(name string) bool { return slices.Contains(k.Names, name) }

// WildcardOverlaps は、この鍵のワイルドカードのパターンのうち、protected のいずれかと重なるものを返す。
func (k Key) WildcardOverlaps(protected []string) []string {
	var out []string
	for _, p := range k.Names {
		if !strings.HasPrefix(p, "*.") {
			continue
		}
		for _, q := range protected {
			if names.Overlap(p, q) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}
