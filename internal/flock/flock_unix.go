//go:build unix

// Package flock は、ファイルを書き換える処理どうしの排他（隣のロックファイルへの flock）を提供する。
// EAB 鍵ファイル・連携情報ファイルの読み込み → 変更 → 書き戻しを、mtlsctl と mtls-ca の間で直列にするために使う。
package flock

import (
	"os"
	"syscall"
)

// Lock は path の隣のロックファイル（path + ".lock"）に排他ロックをかけ、解除する関数を返す。
// 対象のファイル自体は rename で置き換えるので、ロックは別のファイルにかける。
// ロックファイルは空で秘密を含まないので、読み取りだけで開き、権限は 0644 にする。
// root の mtlsctl が先に作っても、mtls-ca（管理画面からの変更）がロックをかけられるようにするため。
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(0o644) // umask に関わらず、もう一方の利用者も開けるようにする（自分が所有者のときだけ効く）
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
