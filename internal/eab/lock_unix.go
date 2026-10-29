//go:build unix

package eab

import (
	"os"
	"syscall"
)

// lockFile は path の隣のロックファイルに排他ロックをかけ、解除する関数を返す。
// 鍵ファイル自体は rename で置き換えるので、ロックは別のファイルにかける。
// ロックファイルは空で秘密を含まないので、読み取りだけで開き、権限は 0644 にする。
// root の mtlsctl が先に作っても、mtls-ca（管理画面からの変更）がロックをかけられるようにするため。
func lockFile(path string) (func(), error) {
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
