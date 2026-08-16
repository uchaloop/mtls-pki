package identity

import (
	"strings"
	"testing"
)

func TestSPIFFE(t *testing.T) {
	if _, err := SPIFFE("spiffe://example.org/ns/default/sa/api"); err != nil {
		t.Fatal(err)
	}

	for _, value := range []string{"https://example.org/a", "spiffe:///a", "spiffe://Example.org/a", "spiffe://example.org/a?x=1"} {
		if _, err := SPIFFE(value); err == nil {
			t.Errorf("accepted invalid SPIFFE ID %q", value)
		}
	}
}

func TestLimits(t *testing.T) {
	if err := Count(MaxSANs); err != nil {
		t.Fatal(err)
	}
	if err := Count(MaxSANs + 1); err == nil {
		t.Fatal("SAN limit not enforced")
	}
	if _, err := URI("urn:test:" + strings.Repeat("x", 2048)); err == nil {
		t.Fatal("URI size limit not enforced")
	}
}
