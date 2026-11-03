package pki

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// CheckPrivateFile は秘密情報のファイルが所有者以外から読み書きできないこと（0600 相当）を確かめる。
// 緩い権限のまま使うと、同じマシンの他ユーザーに鍵を読まれ得るため、起動を拒否する。
func CheckPrivateFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: 通常のファイルではない", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s: 権限が緩すぎる（%04o）。chmod 600 %s を実行すること", path, perm, path)
	}
	return nil
}

// ReadPrivateFile は CheckPrivateFile を通してから読み込む。
func ReadPrivateFile(path string) ([]byte, error) {
	if err := CheckPrivateFile(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// WriteFileAtomic は同じディレクトリの一時ファイルに書いてから rename する。
// 読み手が書きかけのファイルを読むことがない。perm は rename 前に設定し、
// 既存ファイルがあれば所有者・グループを引き継ぐ。
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()
	copyOwner(f, path)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	tmp = ""
	return nil
}

// WriteNewFile は既存ファイルを上書きせずに新規作成する（鍵の誤上書き防止）。
func WriteNewFile(path string, data []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s はすでに存在する（上書きしない）", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
