package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestEncryptedPKCS8RoundTrip(t *testing.T) {
	key, err := GenerateKey(KeyOptions{Algorithm: "ecdsa", Curve: "P-256"})
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := MarshalPrivateKey(key, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatalf("unexpected PEM block: %#v", block)
	}

	parsed, err := ParsePrivateKey(encoded, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}

	a, _ := x509.MarshalPKIXPublicKey(key.Public())
	b, _ := x509.MarshalPKIXPublicKey(parsed.Public())
	if string(a) != string(b) {
		t.Fatal("public keys differ")
	}
	if _, err = ParsePrivateKey(encoded, []byte("wrong")); err == nil {
		t.Fatal("wrong password was accepted")
	}
}

func TestCertificateKeyAndIssuerVerification(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	rootTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}

	root, _ := x509.ParseCertificate(rootDER)
	if err = MatchCertificateKey(root, rootKey); err != nil {
		t.Fatal(err)
	}
	if err = MatchCertificateKey(root, otherKey); err == nil {
		t.Fatal("mismatched key accepted")
	}

	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTpl, root, issuerKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}

	issuer, _ := x509.ParseCertificate(issuerDER)
	if err = VerifyIssuer(root, issuer); err != nil {
		t.Fatal(err)
	}
}
