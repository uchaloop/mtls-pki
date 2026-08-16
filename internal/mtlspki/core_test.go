package mtlspki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWildcardDNS(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
	}{{"*.example.com", true}, {"api.example.com", false}, {"*.*.example.com", false}, {"*.com", false}} {
		if got := validDNS(tc.value, true) == nil; got != tc.ok {
			t.Fatalf("%q: got %v", tc.value, got)
		}
	}
}

func TestStrictProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(`{"serverDayz":30}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path); err == nil {
		t.Fatal("unknown profile field was accepted")
	}
}

func TestInvalidEnvironment(t *testing.T) {
	t.Setenv("MTLS_PKI_SERVER_DAYS", "abc")
	if _, err := applyEnv(baseProfile()); err == nil {
		t.Fatal("invalid environment value was accepted")
	}
}

func TestAlgorithms(t *testing.T) {
	k, err := genKey("ecdsa", 0, "P-256")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := k.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("unexpected key %T", k)
	}
	if _, err = genKey("rsa", 1024, ""); err == nil {
		t.Fatal("expected weak RSA rejection")
	}
}

func TestUnique(t *testing.T) {
	got := unique([]string{"a", "b", "a"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestSPIFFEValidation(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
	}{{"spiffe://example.org/service/api", true}, {"https://example.org/service/api", false}, {"spiffe:///missing-trust-domain", false}, {"spiffe://user@example.org/path", false}, {"spiffe://example.org/path?query=1", false}} {
		if got := validSPIFFE(tc.value) == nil; got != tc.ok {
			t.Fatalf("%q: got %v", tc.value, got)
		}
	}
}

func TestKeyUsageByAlgorithm(t *testing.T) {
	if keyUsageFor("server", "rsa")&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal("RSA server must include keyEncipherment")
	}
	if keyUsageFor("server", "ecdsa")&x509.KeyUsageKeyEncipherment != 0 {
		t.Fatal("ECDSA server must not include keyEncipherment")
	}
}

func TestSchemaVersionCompatibility(t *testing.T) {
	if err := validateSchemaVersion(0); err != nil {
		t.Fatalf("legacy schema must remain readable: %v", err)
	}
	if err := validateSchemaVersion(storageSchemaVersion); err != nil {
		t.Fatalf("current schema rejected: %v", err)
	}
	if err := validateSchemaVersion(storageSchemaVersion + 1); err == nil {
		t.Fatal("future schema was accepted")
	}
}

func TestCLINameRejectsPathSegments(t *testing.T) {
	for _, value := range []string{"", ".", "..", "../pki", "pki/name", "pki\\name"} {
		if validCLIName(value) {
			t.Errorf("dangerous CLI name %q was accepted", value)
		}
	}

	for _, value := range []string{"company", "company.test", "company_test", "company-test"} {
		if !validCLIName(value) {
			t.Errorf("valid CLI name %q was rejected", value)
		}
	}
}

func TestCLINameRejectsOversizedValue(t *testing.T) {
	if validCLIName(strings.Repeat("a", maxCLINameBytes+1)) {
		t.Fatal("oversized CLI name was accepted")
	}
}

func TestCAKeyProtection(t *testing.T) {
	for _, tc := range []struct {
		name             string
		password         []byte
		allowUnencrypted bool
		wantError        bool
	}{
		{name: "missing password", wantError: true},
		{name: "empty password", password: []byte{}, wantError: true},
		{name: "password", password: []byte("secret")},
		{name: "explicit unencrypted", allowUnencrypted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCAKeyProtection(tc.password, tc.allowUnencrypted)
			if (err != nil) != tc.wantError {
				t.Fatalf("validateCAKeyProtection() error = %v, wantError = %v", err, tc.wantError)
			}
		})
	}
}
