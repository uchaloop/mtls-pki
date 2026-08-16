package mtlspki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	pkicore "github.com/uchaloop/mtls-pki/internal/pki"
	secretcore "github.com/uchaloop/mtls-pki/internal/secretinput"
)

type issuerOptions struct {
	storage, pki, format, config, name, typ, algorithm, curve, parentPassEnv, parentPassFile, keyPassEnv, keyPassFile string
	days, bits                                                                                                        int
	dry, parentPassStdin, keyPassStdin, allowActive, allowUnencrypted                                                 bool
}

func makeIssuerCommand(operation string) *cobra.Command {
	o := &issuerOptions{}
	short := "Create an issuing CA"
	if operation == "rotate" {
		short = "Rotate an issuing CA"
	}

	cmd := &cobra.Command{Use: operation, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runIssuer(cmd, operation, o) }}
	f := cmd.Flags()
	f.StringVarP(&o.storage, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&o.pki, "pki", "p", "", "PKI name")
	f.StringVarP(&o.name, "name", "n", "", "issuer name")
	f.StringVarP(&o.typ, "type", "t", "", "server or client")
	f.StringVarP(&o.format, "output", "o", "text", "output format: text or json")
	f.StringVar(&o.config, "config", "", "profile JSON file")
	f.BoolVar(&o.dry, "dry-run", false, "validate without writing files")
	f.IntVarP(&o.days, "days", "D", 0, "validity days")
	f.IntVar(&o.bits, "rsa-bits", 0, "RSA key size")
	f.StringVar(&o.algorithm, "key-algorithm", "", "key algorithm: rsa or ecdsa")
	f.StringVar(&o.curve, "curve", "", "ECDSA curve")
	f.StringVar(&o.parentPassEnv, "parent-pass-env", "", "Root password environment variable")
	f.StringVar(&o.parentPassFile, "parent-pass-file", "", "Root password file")
	f.BoolVar(&o.parentPassStdin, "parent-pass-stdin", false, "read Root password from stdin")
	f.StringVar(&o.keyPassEnv, "key-pass-env", "", "new issuer password environment variable")
	f.StringVar(&o.keyPassFile, "key-pass-file", "", "new issuer password file")
	f.BoolVar(&o.keyPassStdin, "key-pass-stdin", false, "read new issuer password from stdin")
	f.BoolVar(&o.allowUnencrypted, "allow-unencrypted-key", false, "store the issuer private key without encryption")
	if operation == "rotate" {
		f.BoolVar(&o.allowActive, "allow-active-certificates", false, "rotate while valid certificates exist")
	}

	return cmd
}

func runIssuer(cmd *cobra.Command, operation string, o *issuerOptions) error {
	if err := validateCLIName(o.pki, "pki"); err != nil {
		return err
	}
	if err := validateCLIName(o.name, "name"); err != nil {
		return err
	}
	if o.typ != "server" && o.typ != "client" {
		return usageError("--type must be server or client")
	}
	if err := validateFormat(o.format); err != nil {
		return err
	}
	if o.parentPassStdin && o.keyPassStdin {
		return usageError("stdin cannot provide two different passwords")
	}
	if err := validatePasswordSource(o.parentPassEnv, o.parentPassFile, o.parentPassStdin); err != nil {
		return usageError("%v", err)
	}
	if err := validatePasswordSource(o.keyPassEnv, o.keyPassFile, o.keyPassStdin); err != nil {
		return usageError("%v", err)
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
		o.days = profile.IssuerDays
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

	keyPass, err := password(o.keyPassEnv, o.keyPassFile, o.keyPassStdin)
	if err != nil {
		return operational(err)
	}
	defer secretcore.Clear(keyPass)

	if err = validateCAKeyProtection(keyPass, o.allowUnencrypted); err != nil {
		return err
	}

	lock, err := exclusiveLock(o.storage, o.pki)
	if err != nil {
		return err
	}
	defer lock.Close()

	dir := filepath.Join(o.storage, o.pki, "issuers", o.name)
	if err = validateObjectState(dir, operation); err != nil {
		return operational(err)
	}

	generation := uint64(1)
	if operation == "rotate" {
		old, readErr := readIssuerMetadata(dir)
		if readErr != nil {
			return operational(readErr)
		}
		if old.Type != o.typ {
			return operational(fmt.Errorf("issuer type cannot change during rotation"))
		}

		generation = old.Generation + 1
		if !o.allowActive {
			records, readErr := readRecords(filepath.Join(o.storage, o.pki, "index", "certificates.jsonl"))
			if readErr != nil {
				return operational(readErr)
			}

			for _, record := range records {
				if record.Issuer == o.name && record.Status == "valid" {
					return operational(fmt.Errorf("issuer has active certificates; use --allow-active-certificates"))
				}
			}
		}
	}

	parentPass, err := password(o.parentPassEnv, o.parentPassFile, o.parentPassStdin)
	if err != nil {
		return operational(err)
	}
	defer secretcore.Clear(parentPass)

	rootDir := filepath.Join(o.storage, o.pki, "root")
	rootCert, err := parseCert(filepath.Join(rootDir, "certs", "root.crt"))
	if err != nil {
		return operational(err)
	}

	rootKey, err := parseKey(filepath.Join(rootDir, "private", "root.key"), parentPass)
	if err != nil {
		return operational(err)
	}
	if err = pkicore.MatchCertificateKey(rootCert, rootKey); err != nil {
		return operational(err)
	}
	if err = checkParent(rootCert, o.days); err != nil {
		return operational(err)
	}
	if o.dry {
		return emitCobra(cmd, o.format, output{Operation: operation, Type: "issuer", PKI: o.pki, Name: o.name, Algorithm: o.algorithm, Curve: o.curve, RSABits: o.bits, ValidityDays: o.days, OutputDirectory: dir, Message: fmt.Sprintf("dry-run: issuer %s %s (%s), generation %d", operation, o.name, o.typ, generation)})
	}

	stage, cleanup, err := beginObject(dir, operation)
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
	ski, err := pkicore.PublicKeyID(key.Public())
	if err != nil {
		return operational(err)
	}

	template := &x509.Certificate{SerialNumber: serialNumber, Subject: pkix.Name{CommonName: fmt.Sprintf("%s %s %s Issuing CA", o.pki, o.name, o.typ)}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, o.days), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: ski, AuthorityKeyId: rootCert.SubjectKeyId}
	der, err := x509.CreateCertificate(rand.Reader, template, rootCert, key.Public(), rootKey)
	if err != nil {
		return operational(err)
	}

	keyBytes, err := pkicore.MarshalPrivateKey(key, keyPass)
	if err != nil {
		return operational(err)
	}

	certBytes := certPEM(der)
	if err = write(filepath.Join(stage, "certs", "issuer.crt"), certBytes, 0644, false); err != nil {
		return operational(err)
	}
	if err = write(filepath.Join(stage, "private", "issuer.key"), keyBytes, 0600, false); err != nil {
		return operational(err)
	}

	generationBase := generationDir(stage, generation)
	if err = write(filepath.Join(generationBase, "certs", "issuer.crt"), certBytes, 0644, false); err != nil {
		return operational(err)
	}
	if err = write(filepath.Join(generationBase, "private", "issuer.key"), keyBytes, 0600, false); err != nil {
		return operational(err)
	}

	rootGeneration := uint64(1)
	if state, readErr := readRootState(o.storage, o.pki); readErr == nil {
		rootGeneration = state.ActiveGeneration
	}

	issuedCert, err := x509.ParseCertificate(der)
	if err != nil {
		return operational(err)
	}

	meta := metadata{SchemaVersion: storageSchemaVersion, Name: o.name, Type: o.typ, CreatedAt: now, Status: "active", Generation: generation, RootGeneration: rootGeneration, Serial: strings.ToUpper(serialNumber.Text(16)), Fingerprint: fingerprint(issuedCert)}
	metadataBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return operational(err)
	}
	if err = write(filepath.Join(stage, "metadata.json"), append(metadataBytes, '\n'), 0644, false); err != nil {
		return operational(err)
	}
	if operation == "rotate" {
		err = commitIssuerGeneration(dir, stage, generation)
	} else {
		err = commitObject(dir, stage, operation)
	}
	if err != nil {
		return operational(err)
	}

	return emitCobra(cmd, o.format, output{Operation: operation, Type: "issuer", PKI: o.pki, Name: o.name, Certificate: filepath.Join(dir, "certs", "issuer.crt"), PrivateKey: filepath.Join(dir, "private", "issuer.key"), Serial: strings.ToUpper(serialNumber.Text(16)), NotAfter: template.NotAfter.Format(time.RFC3339)})
}
