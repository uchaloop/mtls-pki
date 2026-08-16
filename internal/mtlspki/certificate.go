package mtlspki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uchaloop/mtls-pki/internal/apperr"
	identitycore "github.com/uchaloop/mtls-pki/internal/identity"
	pkicore "github.com/uchaloop/mtls-pki/internal/pki"
	secretcore "github.com/uchaloop/mtls-pki/internal/secretinput"
)

type leafOptions struct {
	storage, pki, format, config, issuer, name, cn, algorithm, curve, issuerPassEnv, issuerPassFile, p12PassEnv, p12PassFile, subjectO, subjectOU, subjectC, subjectST, subjectL string
	days, bits                                                                                                                                                                   int
	dry, issuerPassStdin, p12, p12PassStdin, noCN                                                                                                                                bool
	renewBefore                                                                                                                                                                  time.Duration
	dns, wildcards, ips, uris, spiffe, issuerURLs, crlURLs, ocspURLs                                                                                                             []string
}

func makeLeafCommand(typ, operation string) *cobra.Command {
	o := &leafOptions{}
	verb := "Issue"
	if operation == "renew" {
		verb = "Renew"
	}

	cmd := &cobra.Command{Use: operation, Short: verb + " a " + typ + " certificate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runLeaf(cmd, typ, operation, o) }}
	f := cmd.Flags()
	f.StringVarP(&o.storage, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&o.pki, "pki", "p", "", "PKI name")
	f.StringVarP(&o.issuer, "issuer", "i", "", "issuer name")
	f.StringVarP(&o.name, "name", "n", "", "certificate name")
	f.StringVar(&o.cn, "cn", "", "Subject CN")
	f.BoolVar(&o.noCN, "no-cn", false, "omit Subject CN")
	f.StringSliceVarP(&o.dns, "dns", "d", nil, "exact DNS SAN, repeatable/CSV")
	if typ == "server" {
		f.StringSliceVar(&o.wildcards, "wildcard-dns", nil, "wildcard DNS SAN, repeatable/CSV")
	}

	f.StringSliceVar(&o.ips, "ip", nil, "IP SAN, repeatable/CSV")
	f.StringSliceVar(&o.uris, "uri", nil, "URI SAN, repeatable/CSV")
	f.StringSliceVar(&o.spiffe, "spiffe-id", nil, "SPIFFE URI SAN, repeatable/CSV")
	f.IntVarP(&o.days, "days", "D", 0, "validity days")
	if operation == "renew" {
		f.DurationVar(&o.renewBefore, "renew-before", 0, "renew only when expiry is within duration")
	}

	f.IntVar(&o.bits, "rsa-bits", 0, "RSA key size")
	f.StringVar(&o.algorithm, "key-algorithm", "", "rsa or ecdsa")
	f.StringVar(&o.curve, "curve", "", "P-256 or P-384")
	f.StringVar(&o.issuerPassEnv, "issuer-pass-env", "", "issuer password environment variable")
	f.StringVar(&o.issuerPassFile, "issuer-pass-file", "", "issuer password file")
	f.BoolVar(&o.issuerPassStdin, "issuer-pass-stdin", false, "read issuer password from stdin")
	f.BoolVar(&o.p12, "p12", false, "create PKCS#12")
	f.StringVar(&o.p12PassEnv, "p12-pass-env", "", "PKCS#12 password environment variable")
	f.StringVar(&o.p12PassFile, "p12-pass-file", "", "PKCS#12 password file")
	f.BoolVar(&o.p12PassStdin, "p12-pass-stdin", false, "read PKCS#12 password from stdin")
	f.StringVar(&o.subjectO, "subject-o", "", "Subject O")
	f.StringVar(&o.subjectOU, "subject-ou", "", "Subject OU")
	f.StringVar(&o.subjectC, "subject-c", "", "Subject C")
	f.StringVar(&o.subjectST, "subject-st", "", "Subject ST")
	f.StringVar(&o.subjectL, "subject-l", "", "Subject L")
	f.StringSliceVar(&o.issuerURLs, "issuer-url", nil, "AIA CA Issuers URL, repeatable/CSV")
	f.StringSliceVar(&o.crlURLs, "crl-url", nil, "CRL Distribution Point URL, repeatable/CSV")
	f.StringSliceVar(&o.ocspURLs, "ocsp-url", nil, "AIA OCSP URL, repeatable/CSV")
	f.StringVarP(&o.format, "output", "o", "text", "output format: text or json")
	f.StringVar(&o.config, "config", "", "profile JSON file")
	f.BoolVar(&o.dry, "dry-run", false, "validate without writing files")
	return cmd
}

func runLeaf(cmd *cobra.Command, typ, operation string, o *leafOptions) error {
	if err := validateCLIName(o.pki, "pki"); err != nil {
		return err
	}
	if err := validateCLIName(o.issuer, "issuer"); err != nil {
		return err
	}
	if err := validateCLIName(o.name, "name"); err != nil {
		return err
	}
	if err := validateFormat(o.format); err != nil {
		return err
	}
	if len(o.subjectC) > 0 && !validCountry(o.subjectC) {
		return usageError("--subject-c must contain two letters")
	}
	if o.issuerPassStdin && o.p12PassStdin {
		return usageError("stdin cannot provide issuer and PKCS#12 passwords simultaneously")
	}
	if err := validatePasswordSource(o.issuerPassEnv, o.issuerPassFile, o.issuerPassStdin); err != nil {
		return usageError("%v", err)
	}
	if len(o.p12PassEnv) > 0 || len(o.p12PassFile) > 0 || o.p12PassStdin {
		o.p12 = true
	}
	if o.p12 {
		if err := validatePasswordSource(o.p12PassEnv, o.p12PassFile, o.p12PassStdin); err != nil {
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
		if typ == "server" {
			o.days = profile.ServerDays
		} else {
			o.days = profile.ClientDays
		}
	}
	if o.bits == 0 {
		o.bits = profile.RSABits
	}
	if len(o.algorithm) == 0 {
		o.algorithm = profile.Algorithm
	}
	if len(o.curve) == 0 {
		o.curve = profile.Curve
	}
	if o.days < 1 {
		return usageError("--days must be positive")
	}
	if err = validateKeyOptions(o.algorithm, o.bits, o.curve); err != nil {
		return usageError("%v", err)
	}
	if o.renewBefore < 0 {
		return usageError("--renew-before cannot be negative")
	}

	lock, err := exclusiveLock(o.storage, o.pki)
	if err != nil {
		return err
	}
	defer lock.Close()

	outDir := filepath.Join(o.storage, o.pki, "certificates", typ, o.name)
	if err = validateObjectState(outDir, operation); err != nil {
		return operational(err)
	}
	if operation == "renew" {
		current, readErr := parseCert(filepath.Join(outDir, "certs", typ+".crt"))
		if readErr != nil {
			return operational(readErr)
		}
		if o.renewBefore > 0 && current.NotAfter.After(time.Now().UTC().Add(o.renewBefore)) {
			return apperr.Make(apperr.Renewal, "certificate is not inside renewal window")
		}

		inheritLeafIdentity(o, current)
	}
	if len(o.cn) == 0 {
		o.cn = o.name
	}
	if o.noCN {
		o.cn = ""
	}

	o.dns = unique(o.dns)
	o.wildcards = unique(o.wildcards)
	o.ips = unique(o.ips)
	o.uris = unique(o.uris)
	for _, id := range unique(o.spiffe) {
		if _, err = identitycore.SPIFFE(id); err != nil {
			return usageError("%v", err)
		}

		o.uris = append(o.uris, id)
	}

	o.uris = unique(o.uris)
	for _, wildcard := range o.wildcards {
		if err = validDNS(wildcard, true); err != nil {
			return usageError("%v", err)
		}

		o.dns = append(o.dns, wildcard)
	}

	parsedIPs, parsedURIs, err := validateCSRIdentities(o.dns, o.ips, o.uris)
	if err != nil {
		return usageError("%v", err)
	}

	for label, values := range map[string][]string{"issuer URL": o.issuerURLs, "CRL URL": o.crlURLs, "OCSP URL": o.ocspURLs} {
		if err = validateDistributionURLs(label, values); err != nil {
			return usageError("%v", err)
		}
	}

	issuerDir := filepath.Join(o.storage, o.pki, "issuers", o.issuer)
	meta, err := readIssuerMetadata(issuerDir)
	if err != nil {
		return operational(err)
	}
	if meta.Type != typ || meta.Status != "active" {
		return operational(fmt.Errorf("issuer %s cannot issue active %s certificates", o.issuer, typ))
	}

	certPath, keyPath := activeIssuerPaths(issuerDir, meta)
	issuerCert, err := parseCert(certPath)
	if err != nil {
		return operational(err)
	}

	issuerPass, err := password(o.issuerPassEnv, o.issuerPassFile, o.issuerPassStdin)
	if err != nil {
		return operational(err)
	}
	defer secretcore.Clear(issuerPass)

	issuerKey, err := parseKey(keyPath, issuerPass)
	if err != nil {
		return operational(err)
	}
	if err = pkicore.MatchCertificateKey(issuerCert, issuerKey); err != nil {
		return operational(err)
	}
	if _, err = issuerRoot(filepath.Join(o.storage, o.pki, "root"), issuerCert); err != nil {
		return operational(err)
	}
	if err = checkParent(issuerCert, o.days); err != nil {
		return operational(err)
	}

	subject := pkix.Name{CommonName: o.cn, Organization: nonempty(o.subjectO), OrganizationalUnit: nonempty(o.subjectOU), Country: nonempty(o.subjectC), Province: nonempty(o.subjectST), Locality: nonempty(o.subjectL)}
	if o.dry {
		templateErr := validateLeafPolicyOnly(typ, subject, o.dns, parsedIPs, parsedURIs, issuerCert, o.days, o.algorithm, o.bits, o.curve)
		if templateErr != nil {
			return usageError("%v", templateErr)
		}

		return emitCobra(cmd, o.format, output{Operation: operation, Type: typ, PKI: o.pki, Issuer: o.issuer, Name: o.name, Algorithm: o.algorithm, Curve: o.curve, RSABits: o.bits, ValidityDays: o.days, DNS: o.dns, IP: o.ips, URI: o.uris, OutputDirectory: outDir, Message: fmt.Sprintf("dry-run: %s %s %s via %s", typ, operation, o.name, o.issuer)})
	}

	stage, cleanup, err := beginObject(outDir, operation)
	if err != nil {
		return operational(err)
	}
	defer cleanup()

	key, err := pkicore.GenerateKey(pkicore.KeyOptions{Algorithm: o.algorithm, RSABits: o.bits, Curve: o.curve})
	if err != nil {
		return usageError("%v", err)
	}

	serialNumber, err := serial()
	if err != nil {
		return operational(err)
	}

	now := time.Now().UTC()
	template, err := pkicore.BuildLeafTemplate(pkicore.LeafRequest{Type: typ, Serial: serialNumber, Subject: subject, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, o.days), DNSNames: o.dns, IPAddresses: parsedIPs, URIs: parsedURIs, PublicKey: key.Public(), Issuer: issuerCert, IssuingCertificateURL: unique(o.issuerURLs), CRLDistributionPoints: unique(o.crlURLs), OCSPServer: unique(o.ocspURLs)})
	if err != nil {
		return usageError("%v", err)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuerCert, key.Public(), issuerKey)
	if err != nil {
		return operational(err)
	}

	keyBytes, err := pkicore.MarshalPrivateKey(key, nil)
	if err != nil {
		return operational(err)
	}

	issuerBytes, err := os.ReadFile(certPath)
	if err != nil {
		return operational(err)
	}

	chainRoot, err := issuerRoot(filepath.Join(o.storage, o.pki, "root"), issuerCert)
	if err != nil {
		return operational(err)
	}

	crtStage := filepath.Join(stage, "certs", typ+".crt")
	keyStage := filepath.Join(stage, "private", typ+".key")
	chainStage := filepath.Join(stage, "certs", "chain.crt")
	fullStage := filepath.Join(stage, "certs", "fullchain.crt")
	if err = write(crtStage, certPEM(der), 0644, false); err != nil {
		return operational(err)
	}
	if err = write(keyStage, keyBytes, 0600, false); err != nil {
		return operational(err)
	}
	if err = write(chainStage, append(append([]byte{}, issuerBytes...), certPEM(chainRoot.Raw)...), 0644, false); err != nil {
		return operational(err)
	}
	if err = write(fullStage, append(certPEM(der), issuerBytes...), 0644, false); err != nil {
		return operational(err)
	}

	p12Path := ""
	if o.p12 {
		p12Pass, readErr := password(o.p12PassEnv, o.p12PassFile, o.p12PassStdin)
		if readErr != nil {
			return operational(readErr)
		}
		defer secretcore.Clear(p12Pass)

		p12Stage := filepath.Join(stage, "private", typ+".p12")
		if err = makePKCS12(keyStage, crtStage, chainStage, p12Stage, p12Pass); err != nil {
			return operational(err)
		}

		p12Path = filepath.Join(outDir, "private", typ+".p12")
	}

	crt := filepath.Join(outDir, "certs", typ+".crt")
	rec := record{SchemaVersion: storageSchemaVersion, Serial: strings.ToUpper(serialNumber.Text(16)), PKI: o.pki, Issuer: o.issuer, IssuerGeneration: meta.Generation, IssuerSerial: meta.Serial, IssuerFingerprint: meta.Fingerprint, RootGeneration: meta.RootGeneration, Type: typ, Name: o.name, Subject: subject.String(), DNS: o.dns, IP: o.ips, URI: o.uris, NotBefore: template.NotBefore, NotAfter: template.NotAfter, Certificate: crt, Status: "valid"}
	if err = commitLeafTransaction(outDir, stage, operation, filepath.Join(o.storage, o.pki, "index", "certificates.jsonl"), rec); err != nil {
		return operational(err)
	}

	return emitCobra(cmd, o.format, output{Operation: operation, Type: typ, PKI: o.pki, Issuer: o.issuer, Name: o.name, Certificate: crt, PrivateKey: filepath.Join(outDir, "private", typ+".key"), Chain: filepath.Join(outDir, "certs", "chain.crt"), FullChain: filepath.Join(outDir, "certs", "fullchain.crt"), PKCS12: p12Path, Serial: rec.Serial, NotAfter: template.NotAfter.Format(time.RFC3339)})
}

func inheritLeafIdentity(o *leafOptions, c *x509.Certificate) {
	if len(o.cn) == 0 && !o.noCN {
		o.cn = c.Subject.CommonName
	}
	if len(o.subjectO) == 0 && len(c.Subject.Organization) > 0 {
		o.subjectO = c.Subject.Organization[0]
	}
	if len(o.subjectOU) == 0 && len(c.Subject.OrganizationalUnit) > 0 {
		o.subjectOU = c.Subject.OrganizationalUnit[0]
	}
	if len(o.subjectC) == 0 && len(c.Subject.Country) > 0 {
		o.subjectC = c.Subject.Country[0]
	}
	if len(o.subjectST) == 0 && len(c.Subject.Province) > 0 {
		o.subjectST = c.Subject.Province[0]
	}
	if len(o.subjectL) == 0 && len(c.Subject.Locality) > 0 {
		o.subjectL = c.Subject.Locality[0]
	}
	if len(o.dns)+len(o.wildcards)+len(o.ips)+len(o.uris)+len(o.spiffe) == 0 {
		for _, v := range c.DNSNames {
			if strings.HasPrefix(v, "*.") {
				o.wildcards = append(o.wildcards, v)
			} else {
				o.dns = append(o.dns, v)
			}
		}

		for _, v := range c.IPAddresses {
			o.ips = append(o.ips, v.String())
		}

		for _, v := range c.URIs {
			o.uris = append(o.uris, v.String())
		}
	}
}

func validateLeafPolicyOnly(typ string, subject pkix.Name, dns []string, ips []net.IP, uris []*url.URL, issuer *x509.Certificate, days int, algorithm string, bits int, curve string) error {
	key, err := pkicore.GenerateKey(pkicore.KeyOptions{Algorithm: algorithm, RSABits: bits, Curve: curve})
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	_, err = pkicore.BuildLeafTemplate(pkicore.LeafRequest{Type: typ, Serial: big.NewInt(1), Subject: subject, DNSNames: dns, IPAddresses: ips, URIs: uris, PublicKey: key.Public(), Issuer: issuer, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, days)})
	return err
}
