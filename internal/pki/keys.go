// Package pki は鍵・証明書の生成、署名、読み書きを行う。
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// 鍵の種類。設定ファイル・CLI のフラグで使う。
const (
	KeyECDSAP256 = "ecdsa-p256"
	KeyECDSAP384 = "ecdsa-p384"
	KeyRSA2048   = "rsa-2048"
	KeyRSA3072   = "rsa-3072"
	KeyRSA4096   = "rsa-4096"
	KeyEd25519   = "ed25519"
)

// KeyTypes は指定可能な鍵の種類の一覧。
var KeyTypes = []string{KeyECDSAP256, KeyECDSAP384, KeyRSA2048, KeyRSA3072, KeyRSA4096, KeyEd25519}

// GenerateKey は指定の種類の鍵を生成する。
func GenerateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case KeyECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case KeyRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case KeyEd25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	default:
		return nil, fmt.Errorf("未対応の鍵の種類 %q（%v のいずれか）", keyType, KeyTypes)
	}
}

// CheckPublicKey は証明書に載せてよい公開鍵か（種類と強度）を確かめる。
func CheckPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384():
			return nil
		}
		return errors.New("ECDSA は P-256 / P-384 のみ")
	case *rsa.PublicKey:
		if n := k.N.BitLen(); n < 2048 || n > 8192 {
			return fmt.Errorf("RSA は 2048〜8192 bit（%d bit）", n)
		}
		return nil
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("未対応の鍵 %T", pub)
	}
}

// MarshalPrivateKeyPEM は PKCS#8 の PEM にする。
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM は PKCS#8 / SEC1 (EC) / PKCS#1 (RSA) の PEM を読む。
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("秘密鍵の PEM ブロックが見つからない")
		}
		var (
			k   any
			err error
		)
		switch block.Type {
		case "PRIVATE KEY":
			k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			k, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("暗号化された秘密鍵は未対応（復号してから指定する）")
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("署名に使えない鍵 %T", k)
		}
		return s, nil
	}
}

// LoadPrivateKey は権限を確かめてから秘密鍵ファイルを読む。
func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := ReadPrivateFile(path)
	if err != nil {
		return nil, err
	}
	k, err := ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// SavePrivateKey は秘密鍵を 0600 で新規作成する（既存ファイルは上書きしない）。
func SavePrivateKey(path string, key crypto.Signer) error {
	data, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	return WriteNewFile(path, data, 0o600)
}

// PublicKeyEqual は 2 つの公開鍵が同じかを返す。
func PublicKeyEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}
