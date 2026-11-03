package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "10y": 10 * 365 * 24 * time.Hour, "90s": 90 * time.Second}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "x", "-1d", "1.5d"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("ParseDuration(%q) がエラーにならない", in)
		}
	}
}

// 同梱の設定例がそのまま読めること（設定例と実装の食い違いを防ぐ）。
func TestExamplesLoad(t *testing.T) {
	ca, err := LoadCA(filepath.Join("..", "..", "examples", "ca.example.yaml"))
	if err != nil {
		t.Fatalf("ca.example.yaml: %v", err)
	}
	if ca.Cert.Validity.D() != 24*time.Hour || ca.Hostnames[0] != "ca.internal.example.com" || len(ca.AllowedPrefixes()) != 1 {
		t.Errorf("ca.example.yaml の解釈が想定と違う: %+v", ca)
	}
	ag, err := LoadAgent(filepath.Join("..", "..", "examples", "agent.example.yaml"))
	if err != nil {
		t.Fatalf("agent.example.yaml: %v", err)
	}
	if ag.Challenge.Listen != ":80" || ag.Output.KeyFileMode() != 0o600 {
		t.Errorf("agent.example.yaml の解釈が想定と違う: %+v", ag)
	}
}

func TestUnknownKeyIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("ca_url: https://ca.example.com/acme/directory\nnmaes: [a.example.com]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgent(path); err == nil || !strings.Contains(err.Error(), "nmaes") {
		t.Fatalf("綴り間違いのキーがエラーにならない: %v", err)
	}
}

func TestCARequiresAllowedDomains(t *testing.T) {
	c := &CA{ExternalURL: "https://ca.example.com:8443", DataDir: "d", RootCert: "r", IntermediateCert: "i", IntermediateKey: "k", EABFile: "e"}
	if err := c.Complete(); err == nil || !strings.Contains(err.Error(), "allowed_domains") {
		t.Fatalf("allowed_domains なしで通った: %v", err)
	}
	c.ExternalURL = "http://ca.example.com"
	c.Policy.AllowedDomains = []string{"example.com"}
	if err := c.Complete(); err == nil {
		t.Fatal("http の external_url が通った")
	}
}

func TestCARejectsDuplicateChallengeTypes(t *testing.T) {
	c := &CA{
		ExternalURL: "https://ca.example.com:8443", DataDir: "d", RootCert: "r", IntermediateCert: "i", IntermediateKey: "k", EABFile: "e",
		Policy:    CAPolicy{AllowedDomains: []string{"example.com"}},
		Challenge: CAChallenge{Types: []string{ChallengeHTTP01, ChallengeTLSALPN01, ChallengeHTTP01}},
	}
	if err := c.Complete(); err == nil || !strings.Contains(err.Error(), "重複") {
		t.Fatalf("隣り合わない重複がエラーにならない: %v", err)
	}
}

func TestCAFederationBundleValidity(t *testing.T) {
	base := func(v Duration) *CA {
		return &CA{
			ExternalURL: "https://ca.example.com:8443", DataDir: "d", RootCert: "r", IntermediateCert: "i", IntermediateKey: "k", EABFile: "e",
			Policy:     CAPolicy{AllowedDomains: []string{"example.com"}},
			Federation: CAFederation{File: "f", BundleValidity: v},
		}
	}
	c := base(0)
	if err := c.Complete(); err != nil || c.Federation.BundleValidity.D() != 48*time.Hour {
		t.Fatalf("既定値: %v %v", c.Federation.BundleValidity.D(), err)
	}
	for _, v := range []time.Duration{time.Minute, 8 * 24 * time.Hour} {
		if err := base(Duration(v)).Complete(); err == nil {
			t.Errorf("%v を受け付けた", v)
		}
	}
}
