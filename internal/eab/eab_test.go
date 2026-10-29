package eab

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStoreReflectsFileChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eab.json")
	f := &File{}
	k1, err := f.Add([]string{"Web1.Internal.Example.com"}, "web1")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Lookup(k1.KID)
	if err != nil || !ok {
		t.Fatalf("Lookup: ok=%v err=%v", ok, err)
	}
	if !got.Permits("web1.internal.example.com") || got.Permits("web2.internal.example.com") {
		t.Errorf("Permits が想定と違う: %+v", got.Names)
	}

	// 削除すると、再起動なしで見つからなくなる。
	f.Remove(k1.KID)
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	// 同じ秒内の書き換えでもサイズの違いで検出されるが、念のため mtime も進める。
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)
	if _, ok, err := s.Lookup(k1.KID); err != nil || ok {
		t.Fatalf("削除後も見つかった: ok=%v err=%v", ok, err)
	}
}

func TestLoadRejectsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eab.json")
	f := &File{}
	if _, err := f.Add([]string{"*.internal.example.com"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("0644 の鍵ファイルを読めてしまった")
	}
}

func TestAddRejectsBadPattern(t *testing.T) {
	f := &File{}
	for _, p := range []string{"*", "a.*.example.com", "localhost"} {
		if _, err := f.Add([]string{p}, ""); err == nil {
			t.Errorf("不正なパターン %q を受け付けた", p)
		}
	}
}

// 同時に追加しても、どの変更も失われない。
func TestUpdateIsSerialized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eab.json")
	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Update(path, func(f *File) error {
				_, err := f.Add([]string{"web1.internal.example.com"}, "")
				return err
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Keys) != n {
		t.Fatalf("鍵の数 = %d、want %d（同時の更新で失われた）", len(f.Keys), n)
	}
}
