package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testIssuer(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func baseLeaf(t *testing.T, typ string) LeafRequest {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	return LeafRequest{Type: typ, Serial: big.NewInt(2), Subject: pkix.Name{CommonName: "identity"}, DNSNames: []string{"api.example.com"}, PublicKey: key.Public(), Issuer: testIssuer(t), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour)}
}

func TestBuildLeafTemplateProfiles(t *testing.T) {
	server, err := BuildLeafTemplate(baseLeaf(t, "server"))
	if err != nil {
		t.Fatal(err)
	}
	if server.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal("RSA server is missing KeyEncipherment")
	}
	if len(server.ExtKeyUsage) != 1 || server.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("wrong server EKU")
	}

	clientReq := baseLeaf(t, "client")
	clientReq.DNSNames = nil
	client, err := BuildLeafTemplate(clientReq)
	if err != nil {
		t.Fatal(err)
	}
	if client.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Fatal("client has KeyEncipherment")
	}
	if client.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("wrong client EKU")
	}
}

func TestBuildLeafTemplateRejectsPolicyViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*LeafRequest)
	}{{"client wildcard", func(r *LeafRequest) { r.Type = "client"; r.DNSNames = []string{"*.example.com"} }}, {"server without SAN", func(r *LeafRequest) { r.DNSNames = nil }}, {"too many SANs", func(r *LeafRequest) { r.DNSNames = make([]string, MaxSANs+1) }}, {"subject newline", func(r *LeafRequest) { r.Subject.CommonName = "bad\nname" }}, {"subject too long", func(r *LeafRequest) { r.Subject.CommonName = strings.Repeat("x", MaxSubjectValueBytes+1) }}, {"past issuer", func(r *LeafRequest) { r.NotAfter = r.Issuer.NotAfter.Add(time.Second) }}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := baseLeaf(t, "server")
			tt.mutate(&request)
			if _, err := BuildLeafTemplate(request); err == nil {
				t.Fatal("policy violation was accepted")
			}
		})
	}
}
