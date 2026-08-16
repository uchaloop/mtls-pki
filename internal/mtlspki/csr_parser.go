package mtlspki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
)

func parseCSR(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseCSRBytes(data)
}

func parseCSRBytes(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR")
	}

	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err = request.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	return request, nil
}

func ipsToStrings(values []net.IP) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = value.String()
	}

	return out
}

func urisToStrings(values []*url.URL) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = value.String()
	}

	return out
}
