package config

import (
	"strings"
	"testing"

	"github.com/nobumin/mtls_manager/internal/i18n"
)

// MTLS_LANG=en のとき、設定の誤りは英語で返す（既定の日本語のときの文言は、ほかのテストが確かめている）。
func TestValidationErrorsInEnglish(t *testing.T) {
	t.Cleanup(i18n.Set(i18n.English))
	c := &CA{ExternalURL: "https://ca.example.com:8443", DataDir: "d", RootCert: "r", IntermediateCert: "i", IntermediateKey: "k", EABFile: "e"}
	if err := c.Complete(); err == nil || !strings.Contains(err.Error(), "policy.allowed_domains is required") {
		t.Fatalf("英語のエラーにならない: %v", err)
	}
	if _, err := ParseDuration("x"); err == nil || !strings.Contains(err.Error(), "cannot parse duration") {
		t.Fatalf("英語のエラーにならない: %v", err)
	}
}
