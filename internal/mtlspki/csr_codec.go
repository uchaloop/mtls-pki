package mtlspki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	pkicore "github.com/uchaloop/mtls-pki/internal/pki"
	secretcore "github.com/uchaloop/mtls-pki/internal/secretinput"
)

func makeCSRInspectCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{Use: "inspect CSR", Short: "Inspect and verify a CSR", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFormat(format); err != nil {
			return err
		}

		csr, err := parseCSR(args[0])
		if err != nil {
			return operational(err)
		}

		value := map[string]any{"subject": csr.Subject.String(), "dns": csr.DNSNames, "ip": csr.IPAddresses, "uri": csr.URIs, "signatureValid": true}
		if format == "json" {
			data, _ := json.MarshalIndent(value, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "subject: %s\nsignature valid: true\nDNS: %v\nIP: %v\nURI: %v\n", csr.Subject, csr.DNSNames, csr.IPAddresses, csr.URIs)
		}

		return nil
	}}

	cmd.Flags().StringVarP(&format, "output", "o", "json", "output format: text or json")
	return cmd
}

type csrCreateOptions struct {
	name, cn, algorithm, curve, out, passEnv, passFile, format string
	bits                                                       int
	force, passStdin                                           bool
	dns, ips, uris                                             []string
}

func makeCSRCreateCommand() *cobra.Command {
	o := &csrCreateOptions{}
	cmd := &cobra.Command{Use: "create", Short: "Create a private key and CSR", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runCSRCreate(cmd, o) }}
	f := cmd.Flags()
	f.StringVarP(&o.name, "name", "n", "", "request name")
	f.StringVar(&o.cn, "cn", "", "Subject CN (default name)")
	f.StringSliceVarP(&o.dns, "dns", "d", nil, "DNS SAN, repeatable/CSV")
	f.StringSliceVar(&o.ips, "ip", nil, "IP SAN, repeatable/CSV")
	f.StringSliceVar(&o.uris, "uri", nil, "URI SAN, repeatable/CSV")
	f.StringVar(&o.algorithm, "key-algorithm", "ecdsa", "key algorithm: rsa or ecdsa")
	f.IntVar(&o.bits, "rsa-bits", 3072, "RSA key size")
	f.StringVar(&o.curve, "curve", "P-256", "ECDSA curve: P-256 or P-384")
	f.StringVarP(&o.out, "out", "O", ".", "output directory")
	f.BoolVarP(&o.force, "force", "f", false, "replace output files")
	f.StringVar(&o.passEnv, "key-pass-env", "", "password environment variable")
	f.StringVar(&o.passFile, "key-pass-file", "", "password file")
	f.BoolVar(&o.passStdin, "key-pass-stdin", false, "read password from stdin")
	f.StringVarP(&o.format, "output", "o", "text", "output format: text or json")
	return cmd
}

func runCSRCreate(cmd *cobra.Command, o *csrCreateOptions) error {
	if err := validateCLIName(o.name, "name"); err != nil {
		return err
	}
	if err := validateFormat(o.format); err != nil {
		return err
	}
	if len(o.cn) == 0 {
		o.cn = o.name
	}
	if err := validateKeyOptions(o.algorithm, o.bits, o.curve); err != nil {
		return usageError("%v", err)
	}
	if err := validatePasswordSource(o.passEnv, o.passFile, o.passStdin); err != nil {
		return usageError("%v", err)
	}

	o.dns = unique(o.dns)
	o.ips = unique(o.ips)
	o.uris = unique(o.uris)
	parsedIPs, parsedURIs, err := validateCSRIdentities(o.dns, o.ips, o.uris)
	if err != nil {
		return usageError("%v", err)
	}

	key, err := pkicore.GenerateKey(pkicore.KeyOptions{Algorithm: o.algorithm, RSABits: o.bits, Curve: o.curve})
	if err != nil {
		return usageError("%v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: o.cn}, DNSNames: o.dns, IPAddresses: parsedIPs, URIs: parsedURIs}, key)
	if err != nil {
		return operational(err)
	}

	pass, err := password(o.passEnv, o.passFile, o.passStdin)
	if err != nil {
		return operational(err)
	}
	defer secretcore.Clear(pass)

	keyPEM, err := pkicore.MarshalPrivateKey(key, pass)
	if err != nil {
		return operational(err)
	}

	csrPath := filepath.Join(o.out, o.name+".csr")
	keyPath := filepath.Join(o.out, o.name+".key")
	if err = write(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0644, o.force); err != nil {
		return operational(err)
	}
	if err = write(keyPath, keyPEM, 0600, o.force); err != nil {
		return operational(err)
	}
	if o.format == "json" {
		data, _ := json.Marshal(map[string]string{"operation": "csr-create", "csr": csrPath, "privateKey": keyPath})
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "CSR:", csrPath)
		fmt.Fprintln(cmd.OutOrStdout(), "private key:", keyPath)
	}

	return nil
}

type csrSignOptions struct {
	root, pki, issuer, typ, name, csr, config, passEnv, passFile, format string
	days                                                                 int
	passStdin                                                            bool
	issuerURLs, crlURLs, ocspURLs                                        []string
}

func makeCSRSignCommand() *cobra.Command {
	o := &csrSignOptions{}
	cmd := &cobra.Command{Use: "sign", Short: "Sign a CSR with an issuing CA", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runCSRSign(cmd, o) }}
	f := cmd.Flags()
	f.StringVarP(&o.root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&o.pki, "pki", "p", "", "PKI name")
	f.StringVarP(&o.issuer, "issuer", "i", "", "issuer name")
	f.StringVarP(&o.typ, "type", "t", "", "server or client")
	f.StringVarP(&o.name, "name", "n", "", "certificate name")
	f.StringVar(&o.csr, "csr", "", "CSR path")
	f.StringVar(&o.config, "config", "", "profile JSON file")
	f.IntVarP(&o.days, "days", "D", 0, "validity days")
	f.StringVar(&o.passEnv, "issuer-pass-env", "", "issuer password environment variable")
	f.StringVar(&o.passFile, "issuer-pass-file", "", "issuer password file")
	f.BoolVar(&o.passStdin, "issuer-pass-stdin", false, "read issuer password from stdin")
	f.StringSliceVar(&o.issuerURLs, "issuer-url", nil, "AIA CA Issuers URL, repeatable/CSV")
	f.StringSliceVar(&o.crlURLs, "crl-url", nil, "CRL Distribution Point URL, repeatable/CSV")
	f.StringSliceVar(&o.ocspURLs, "ocsp-url", nil, "AIA OCSP URL, repeatable/CSV")
	f.StringVarP(&o.format, "output", "o", "text", "output format: text or json")
	return cmd
}

func runCSRSign(cmd *cobra.Command, o *csrSignOptions) error {
	if err := validateCLIName(o.pki, "pki"); err != nil {
		return err
	}
	if err := validateCLIName(o.issuer, "issuer"); err != nil {
		return err
	}
	if err := validateCLIName(o.name, "name"); err != nil {
		return err
	}
	if o.typ != "server" && o.typ != "client" {
		return usageError("--type must be server or client")
	}
	if len(o.csr) == 0 {
		return usageError("--csr is required")
	}
	if err := validateFormat(o.format); err != nil {
		return err
	}
	if err := validatePasswordSource(o.passEnv, o.passFile, o.passStdin); err != nil {
		return usageError("%v", err)
	}

	for label, values := range map[string][]string{"issuer URL": o.issuerURLs, "CRL URL": o.crlURLs, "OCSP URL": o.ocspURLs} {
		if err := validateDistributionURLs(label, values); err != nil {
			return usageError("%v", err)
		}
	}

	profile, err := loadProfile(o.config)
	if err != nil {
		return usageError("%v", err)
	}

	profile, err = applyEnv(profile)
	if err != nil {
		return usageError("%v", err)
	}
	if o.days == 0 {
		if o.typ == "server" {
			o.days = profile.ServerDays
		} else {
			o.days = profile.ClientDays
		}
	}
	if o.days < 1 {
		return usageError("--days must be positive")
	}

	lock, err := exclusiveLock(o.root, o.pki)
	if err != nil {
		return err
	}
	defer lock.Close()

	request, err := parseCSR(o.csr)
	if err != nil {
		return operational(err)
	}
	if _, _, err = validateCSRIdentities(request.DNSNames, ipsToStrings(request.IPAddresses), urisToStrings(request.URIs)); err != nil {
		return usageError("%v", err)
	}

	issuerDir := filepath.Join(o.root, o.pki, "issuers", o.issuer)
	meta, err := readIssuerMetadata(issuerDir)
	if err != nil {
		return operational(err)
	}
	if meta.Type != o.typ || meta.Status != "active" {
		return operational(fmt.Errorf("issuer type or status does not permit signing"))
	}

	certPath, keyPath := activeIssuerPaths(issuerDir, meta)
	issuerCert, err := parseCert(certPath)
	if err != nil {
		return operational(err)
	}

	pass, err := password(o.passEnv, o.passFile, o.passStdin)
	if err != nil {
		return operational(err)
	}
	defer secretcore.Clear(pass)

	issuerKey, err := parseKey(keyPath, pass)
	if err != nil {
		return operational(err)
	}
	if err = pkicore.MatchCertificateKey(issuerCert, issuerKey); err != nil {
		return operational(err)
	}
	if err = checkParent(issuerCert, o.days); err != nil {
		return operational(err)
	}

	serialNumber, err := serial()
	if err != nil {
		return operational(err)
	}

	now := time.Now().UTC()
	template, err := pkicore.BuildLeafTemplate(pkicore.LeafRequest{Type: o.typ, Serial: serialNumber, Subject: request.Subject, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, o.days), DNSNames: request.DNSNames, IPAddresses: request.IPAddresses, URIs: request.URIs, PublicKey: request.PublicKey, Issuer: issuerCert, IssuingCertificateURL: unique(o.issuerURLs), CRLDistributionPoints: unique(o.crlURLs), OCSPServer: unique(o.ocspURLs)})
	if err != nil {
		return usageError("CSR violates %s policy: %v", o.typ, err)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuerCert, request.PublicKey, issuerKey)
	if err != nil {
		return operational(err)
	}

	outDir := filepath.Join(o.root, o.pki, "certificates", o.typ, o.name)
	stage, cleanup, err := beginObject(outDir, "issue")
	if err != nil {
		return operational(err)
	}
	defer cleanup()

	issuerBytes, err := os.ReadFile(certPath)
	if err != nil {
		return operational(err)
	}

	chainRoot, err := issuerRoot(filepath.Join(o.root, o.pki, "root"), issuerCert)
	if err != nil {
		return operational(err)
	}

	crt := filepath.Join(outDir, "certs", o.typ+".crt")
	if err = write(filepath.Join(stage, "certs", o.typ+".crt"), certPEM(der), 0644, false); err != nil {
		return operational(err)
	}
	if err = write(filepath.Join(stage, "certs", "chain.crt"), append(append([]byte{}, issuerBytes...), certPEM(chainRoot.Raw)...), 0644, false); err != nil {
		return operational(err)
	}
	if err = write(filepath.Join(stage, "certs", "fullchain.crt"), append(certPEM(der), issuerBytes...), 0644, false); err != nil {
		return operational(err)
	}

	rec := record{SchemaVersion: storageSchemaVersion, Serial: strings.ToUpper(serialNumber.Text(16)), PKI: o.pki, Issuer: o.issuer, IssuerGeneration: meta.Generation, IssuerSerial: meta.Serial, IssuerFingerprint: meta.Fingerprint, RootGeneration: meta.RootGeneration, Type: o.typ, Name: o.name, Subject: request.Subject.String(), DNS: request.DNSNames, IP: ipsToStrings(request.IPAddresses), URI: urisToStrings(request.URIs), NotBefore: template.NotBefore, NotAfter: template.NotAfter, Certificate: crt, Status: "valid"}
	if err = commitLeafTransaction(outDir, stage, "issue", filepath.Join(o.root, o.pki, "index", "certificates.jsonl"), rec); err != nil {
		return operational(err)
	}
	if o.format == "json" {
		data, _ := json.Marshal(map[string]any{"operation": "csr-sign", "certificate": crt, "serial": rec.Serial, "notAfter": template.NotAfter})
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "certificate:", crt)
	}

	return nil
}

const maxCLINameBytes = 128

func validCLIName(value string) bool {
	if len(value) == 0 || len(value) > maxCLINameBytes || value == "." || value == ".." {
		return false
	}

	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}

	return true
}

func validateCLIName(value, flag string) error {
	if !validCLIName(value) {
		return usageError(
			"--%s is required and may contain up to %d letters, digits, dots, underscores and hyphens",
			flag,
			maxCLINameBytes,
		)
	}

	return nil
}

func validateCSRIdentities(dns, ips, uris []string) ([]net.IP, []*url.URL, error) {
	if len(dns)+len(ips)+len(uris) > pkicore.MaxSANs {
		return nil, nil, fmt.Errorf("too many SAN values (maximum %d)", pkicore.MaxSANs)
	}

	for _, value := range dns {
		if err := validDNS(value, strings.HasPrefix(value, "*.")); err != nil {
			return nil, nil, err
		}
	}

	parsedIPs := make([]net.IP, 0, len(ips))
	for _, value := range ips {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP SAN: %s", value)
		}

		parsedIPs = append(parsedIPs, ip)
	}

	parsedURIs := make([]*url.URL, 0, len(uris))
	for _, value := range uris {
		parsed, err := url.ParseRequestURI(value)
		if err != nil || len(parsed.Scheme) == 0 {
			return nil, nil, fmt.Errorf("invalid URI SAN: %s", value)
		}

		parsedURIs = append(parsedURIs, parsed)
	}

	return parsedIPs, parsedURIs, nil
}
