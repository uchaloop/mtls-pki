package mtlspki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestCRLMatchesLeafIssuerFromVerifiedChain(t *testing.T) {
	t.Parallel()

	issuer, issuerKey := makeTestCA(t, "issuer", 1)
	otherIssuer, otherIssuerKey := makeTestCA(t, "other-issuer", 2)
	leaf := makeTestLeaf(t, issuer, issuerKey)
	crl := makeTestCRL(t, otherIssuer, otherIssuerKey)

	chains := [][]*x509.Certificate{{leaf, issuer}}
	if crlMatchesVerifiedChain(crl, chains) {
		t.Fatal("CRL signed by another issuer was accepted")
	}

	crl = makeTestCRL(t, issuer, issuerKey)
	if !crlMatchesVerifiedChain(crl, chains) {
		t.Fatal("CRL signed by the leaf issuer was rejected")
	}
}

func makeTestCA(t *testing.T, name string, serial int64) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return certificate, key
}

func makeTestLeaf(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		issuer,
		key.Public(),
		issuerKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return certificate
}

func makeTestCRL(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
) *x509.RevocationList {
	t.Helper()

	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(
		rand.Reader,
		&x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now.Add(-time.Minute),
			NextUpdate: now.Add(time.Hour),
		},
		issuer,
		issuerKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}

	return crl
}
