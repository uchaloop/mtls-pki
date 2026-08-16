package mtlspki

import (
	"strings"
	"testing"
)

func TestKubernetesDNSSubdomainValidation(t *testing.T) {
	for _, value := range []string{"mtls-certificate", "api.tls", "a1-b2.example"} {
		if err := validateKubernetesDNSSubdomain(value, "secret-name"); err != nil {
			t.Errorf("valid subdomain %q was rejected: %v", value, err)
		}
	}

	for _, value := range []string{
		"",
		"Uppercase",
		"-prefix",
		"suffix-",
		"two..dots",
		"name\n  labels: injected",
		strings.Repeat("a", 254),
	} {
		if err := validateKubernetesDNSSubdomain(value, "secret-name"); err == nil {
			t.Errorf("invalid subdomain %q was accepted", value)
		}
	}
}

func TestKubernetesDNSLabelValidation(t *testing.T) {
	for _, value := range []string{"default", "efiro-test", "ns1"} {
		if err := validateKubernetesDNSLabel(value, "namespace"); err != nil {
			t.Errorf("valid label %q was rejected: %v", value, err)
		}
	}

	for _, value := range []string{"", "namespace.example", "Uppercase", "bad_name", strings.Repeat("a", 64)} {
		if err := validateKubernetesDNSLabel(value, "namespace"); err == nil {
			t.Errorf("invalid label %q was accepted", value)
		}
	}
}
