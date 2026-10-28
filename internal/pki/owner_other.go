//go:build !unix

package pki

import "os"

func copyOwner(*os.File, string) {}
