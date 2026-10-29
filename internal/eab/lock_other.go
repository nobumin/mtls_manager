//go:build !unix

package eab

func lockFile(string) (func(), error) { return func() {}, nil }
