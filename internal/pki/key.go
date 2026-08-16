package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	pkcs8lib "github.com/youmark/pkcs8"
)

type KeyOptions struct {
	Algorithm string
	RSABits   int
	Curve     string
}

func GenerateKey(o KeyOptions) (crypto.Signer, error) {
	switch o.Algorithm {
	case "rsa":
		if o.RSABits != 2048 && o.RSABits != 3072 && o.RSABits != 4096 {
			return nil, errors.New("RSA bits must be 2048, 3072 or 4096")
		}

		return rsa.GenerateKey(rand.Reader, o.RSABits)
	case "ecdsa":
		switch o.Curve {
		case "P-256", "prime256v1":
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "P-384", "secp384r1":
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		default:
			return nil, errors.New("curve must be P-256 or P-384")
		}
	default:
		return nil, errors.New("algorithm must be rsa or ecdsa")
	}
}

var encryptedOpts = &pkcs8lib.Opts{Cipher: pkcs8lib.AES256CBC, KDFOpts: pkcs8lib.PBKDF2Opts{SaltSize: 16, IterationCount: 600000, HMACHash: crypto.SHA256}}

func MarshalPrivateKey(key crypto.Signer, password []byte) ([]byte, error) {
	var der []byte
	var e error

	if len(password) == 0 {
		der, e = x509.MarshalPKCS8PrivateKey(key)
	} else {
		der, e = pkcs8lib.MarshalPrivateKey(key, password, encryptedOpts)
	}

	if e != nil {
		return nil, e
	}

	typ := "PRIVATE KEY"
	if len(password) > 0 {
		typ = "ENCRYPTED PRIVATE KEY"
	}

	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), nil
}

func ParsePrivateKey(data, password []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}

	var key any
	var e error

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		if len(password) == 0 {
			return nil, errors.New("private key is encrypted")
		}

		key, e = pkcs8lib.ParsePKCS8PrivateKey(block.Bytes, password)
	} else {
		key, e = x509.ParsePKCS8PrivateKey(block.Bytes)
	}

	if e != nil {
		return nil, e
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a signer")
	}

	return signer, nil
}

func PublicKeyID(public any) ([]byte, error) {
	der, e := x509.MarshalPKIXPublicKey(public)
	if e != nil {
		return nil, e
	}

	sum := sha256.Sum256(der)

	return sum[:], nil
}

func MatchCertificateKey(cert *x509.Certificate, key crypto.Signer) error {
	a, e := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if e != nil {
		return e
	}

	b, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		return e
	}

	if !cryptoBytesEqual(a, b) {
		return errors.New("certificate and private key do not match")
	}

	return nil
}

func cryptoBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}

	return v == 0
}

func VerifyIssuer(root, issuer *x509.Certificate) error {
	pool := x509.NewCertPool()
	pool.AddCert(root)

	_, e := issuer.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})

	return e
}
