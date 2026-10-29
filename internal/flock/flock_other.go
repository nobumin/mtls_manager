//go:build !unix

package flock

// Lock は、flock の無い OS では何もしない。
func Lock(string) (func(), error) { return func() {}, nil }
