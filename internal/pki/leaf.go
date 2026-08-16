package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

const MaxSANs = 100
const MaxSubjectValueBytes = 1024

type LeafRequest struct {
	Type                                                     string
	Serial                                                   *big.Int
	Subject                                                  pkix.Name
	DNSNames                                                 []string
	IPAddresses                                              []net.IP
	URIs                                                     []*url.URL
	PublicKey                                                any
	Issuer                                                   *x509.Certificate
	NotBefore, NotAfter                                      time.Time
	IssuingCertificateURL, CRLDistributionPoints, OCSPServer []string
}

func BuildLeafTemplate(r LeafRequest) (*x509.Certificate, error) {
	if r.Type != "server" && r.Type != "client" {
		return nil, errors.New("certificate type must be server or client")
	}
	if r.Serial == nil || r.Serial.Sign() <= 0 {
		return nil, errors.New("serial must be positive")
	}
	if r.Issuer == nil || !r.Issuer.IsCA {
		return nil, errors.New("issuer must be a CA certificate")
	}
	if r.PublicKey == nil {
		return nil, errors.New("public key is required")
	}
	if !r.NotAfter.After(r.NotBefore) {
		return nil, errors.New("NotAfter must be after NotBefore")
	}
	if r.NotAfter.After(r.Issuer.NotAfter) {
		return nil, errors.New("leaf validity exceeds issuer validity")
	}
	if len(r.DNSNames)+len(r.IPAddresses)+len(r.URIs) > MaxSANs {
		return nil, fmt.Errorf("too many SAN values (maximum %d)", MaxSANs)
	}
	if err := validateSubject(r.Subject); err != nil {
		return nil, err
	}

	for _, dns := range r.DNSNames {
		if r.Type == "client" && strings.Contains(dns, "*") {
			return nil, errors.New("wildcard DNS SAN is not allowed in client certificates")
		}
	}
	if r.Type == "server" && len(r.DNSNames)+len(r.IPAddresses)+len(r.URIs) == 0 {
		return nil, errors.New("server certificate requires at least one SAN")
	}
	if r.Type == "client" && len(r.Subject.String()) == 0 && len(r.DNSNames)+len(r.IPAddresses)+len(r.URIs) == 0 {
		return nil, errors.New("client certificate requires a Subject or SAN identity")
	}

	ski, err := PublicKeyID(r.PublicKey)
	if err != nil {
		return nil, err
	}

	usage := x509.KeyUsageDigitalSignature
	if r.Type == "server" {
		if _, ok := r.PublicKey.(*rsa.PublicKey); ok {
			usage |= x509.KeyUsageKeyEncipherment
		}
	}

	eku := x509.ExtKeyUsageClientAuth
	if r.Type == "server" {
		eku = x509.ExtKeyUsageServerAuth
	}

	return &x509.Certificate{
		SerialNumber:          r.Serial,
		Subject:               r.Subject,
		NotBefore:             r.NotBefore,
		NotAfter:              r.NotAfter,
		BasicConstraintsValid: true,
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		DNSNames:              r.DNSNames,
		IPAddresses:           r.IPAddresses,
		URIs:                  r.URIs,
		SubjectKeyId:          ski,
		AuthorityKeyId:        r.Issuer.SubjectKeyId,
		IssuingCertificateURL: r.IssuingCertificateURL,
		CRLDistributionPoints: r.CRLDistributionPoints,
		OCSPServer:            r.OCSPServer,
	}, nil
}

func validateSubject(subject pkix.Name) error {
	values := []string{subject.CommonName}
	values = append(values, subject.Organization...)
	values = append(values, subject.OrganizationalUnit...)
	values = append(values, subject.Country...)
	values = append(values, subject.Province...)
	values = append(values, subject.Locality...)
	values = append(values, subject.StreetAddress...)
	values = append(values, subject.PostalCode...)

	for _, value := range values {
		if strings.ContainsAny(value, "\r\n") {
			return errors.New("Subject values cannot contain CR or LF")
		}
		if len(value) > MaxSubjectValueBytes {
			return fmt.Errorf("Subject value exceeds %d bytes", MaxSubjectValueBytes)
		}
	}

	return nil
}
