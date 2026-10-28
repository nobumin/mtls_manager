package names

import "testing"

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		p, name string
		want    bool
	}{
		{"web1.example.com", "web1.example.com", true},
		{"web1.example.com", "web2.example.com", false},
		{"*.example.com", "web1.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "web1.example.org", false},
		{"*.example.com", "xexample.com", false},
	}
	for _, c := range cases {
		if got := MatchPattern(c.p, c.name); got != c.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", c.p, c.name, got, c.want)
		}
	}
}

func TestWithinDomain(t *testing.T) {
	cases := []struct {
		d, name string
		want    bool
	}{
		{"internal.example.com", "internal.example.com", true},
		{"internal.example.com", "a.b.internal.example.com", true},
		{"internal.example.com", "evilinternal.example.com", false},
		{"internal.example.com", "example.com", false},
	}
	for _, c := range cases {
		if got := WithinDomain(c.d, c.name); got != c.want {
			t.Errorf("WithinDomain(%q, %q) = %v, want %v", c.d, c.name, got, c.want)
		}
	}
}

func TestValidateHostname(t *testing.T) {
	ok := []string{"web1.example.com", "a-b.c1.example.com", "xn--eckwd4c7c.example.jp"}
	for _, n := range ok {
		if err := ValidateHostname(n); err != nil {
			t.Errorf("ValidateHostname(%q) = %v", n, err)
		}
	}
	ng := []string{"", "localhost", "10.0.0.1", "a.123", "*.example.com", "-a.example.com", "a..example.com", "a_b.example.com", "A.example.com"}
	for _, n := range ng {
		if err := ValidateHostname(n); err == nil {
			t.Errorf("ValidateHostname(%q) = nil, want error", n)
		}
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize(" Web1.Example.COM. "); got != "web1.example.com" {
		t.Errorf("Normalize = %q", got)
	}
}

func TestValidateDomain(t *testing.T) {
	for _, d := range []string{"corp", "internal.example.com"} {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("ValidateDomain(%q) = %v", d, err)
		}
	}
	for _, d := range []string{"", "10", "a..b", "-corp"} {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("ValidateDomain(%q) = nil, want error", d)
		}
	}
}
