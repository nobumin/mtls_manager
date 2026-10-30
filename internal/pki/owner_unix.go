//go:build unix

package pki

import (
	"os"
	"syscall"
)

// copyOwner は既存ファイルの所有者・グループを f に引き継ぐ（root で mtlsctl を実行しても、
// サービス用ユーザーが読めるファイルのままにするため）。権限が無ければ何もしない。
func copyOwner(f *os.File, path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = f.Chown(int(st.Uid), int(st.Gid))
	}
}
