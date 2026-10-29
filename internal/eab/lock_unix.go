//go:build unix

package eab

import (
	"os"
	"syscall"
)

// lockFile は path の隣のロックファイルに排他ロックをかけ、解除する関数を返す。
// 鍵ファイル自体は rename で置き換えるので、ロックは別のファイルにかける。
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
