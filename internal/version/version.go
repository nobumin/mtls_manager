// Package version はビルド時に埋め込むバージョン情報を保持する。
package version

// Version はリリース時に -ldflags "-X github.com/nobumin/mtls_manager/internal/version.Version=v1.2.3" で上書きする。
var Version = "dev"
