package mtlspki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	pkicore "github.com/uchaloop/mtls-pki/internal/pki"
	secretcore "github.com/uchaloop/mtls-pki/internal/secretinput"
)

type rootOptions struct {
	storage, pki, format, config, algorithm, curve, passEnv, passFile, subjectO, subjectOU, subjectC, subjectST, subjectL string
	days, bits                                                                                                            int
	dry, passStdin, allowUnencrypted                                                                                      bool
}

func makeRootCommand(operation string) *cobra.Command {
	o := &rootOptions{}
	short := "Create an offline Root CA"
	if operation == "rotate" {
		short = "Begin a compatible Root CA rotation"
	}

	cmd := &cobra.Command{Use: operation, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runRoot(cmd, operation, o) }}
	f := cmd.Flags()
	f.StringVarP(&o.storage, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&o.pki, "pki", "p", "", "PKI name")
	f.StringVarP(&o.format, "output", "o", "text", "output format: text or json")
	f.StringVar(&o.config, "config", "", "profile JSON file")
	f.BoolVar(&o.dry, "dry-run", false, "validate without writing files")
	f.IntVarP(&o.days, "days", "D", 0, "validity days")
	f.IntVar(&o.bits, "rsa-bits", 0, "RSA key size")
	f.StringVar(&o.algorithm, "key-algorithm", "", "key algorithm: rsa or ecdsa")
	f.StringVar(&o.curve, "curve", "", "ECDSA curve")
	f.StringVar(&o.passEnv, "key-pass-env", "", "password environment variable")
	f.StringVar(&o.passFile, "key-pass-file", "", "password file")
	f.BoolVar(&o.passStdin, "key-pass-stdin", false, "read password from stdin")
	f.BoolVar(&o.allowUnencrypted, "allow-unencrypted-key", false, "store the Root private key without encryption")
	f.StringVar(&o.subjectO, "subject-o", "", "Subject O")
	f.StringVar(&o.subjectOU, "subject-ou", "", "Subject OU")
	f.StringVar(&o.subjectC, "subject-c", "", "Subject C")
	f.StringVar(&o.subjectST, "subject-st", "", "Subject ST")
	f.StringVar(&o.subjectL, "subject-l", "", "Subject L")
	return cmd
}

func runRoot(cmd *cobra.Command, operation string, o *rootOptions) error {
	if err := validateCLIName(o.pki, "pki"); err != nil {
		return err
	}
	if err := validateFormat(o.format); err != nil {
		return err
	}
	if len(o.subjectC) > 0 && !validCountry(o.subjectC) {
		return usageError("--subject-c must contain two letters")
	}
	if err := validatePasswordSource(o.passEnv, o.passFile, o.passStdin); err != nil {
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
		o.days = profile.RootDays
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

	pass, err := password(o.passEnv, o.passFile, o.passStdin)
	if err != nil {
		return operational(err)
	}
	defer secretcore.Clear(pass)

	if err = validateCAKeyProtection(pass, o.allowUnencrypted); err != nil {
		return err
	}

	lock, err := exclusiveLock(o.storage, o.pki)
	if err != nil {
		return err
	}
	defer lock.Close()

	dir := filepath.Join(o.storage, o.pki, "root")
	if err = validateObjectState(dir, operation); err != nil {
		return operational(err)
	}

	generation := uint64(1)
	var previousBundle []byte
	if operation == "rotate" {
		state, readErr := readRootState(o.storage, o.pki)
		if readErr != nil {
			return readErr
		}
		if state.Rotation != nil {
			return operational(fmt.Errorf("Root rotation is already in progress"))
		}

		generation = state.ActiveGeneration + 1
		bundlePath := filepath.Join(dir, "certs", "trust-bundle.crt")
		if !exists(bundlePath) {
			bundlePath = filepath.Join(dir, "certs", "root.crt")
		}

		previousBundle, err = os.ReadFile(bundlePath)
		if err != nil {
			return operational(err)
		}
	}
	if o.dry {
		result := output{Operation: operation, Type: "root", PKI: o.pki, Algorithm: o.algorithm, Curve: o.curve, RSABits: o.bits, ValidityDays: o.days, OutputDirectory: dir, Message: fmt.Sprintf("dry-run: root %s %s, generation %d", operation, o.pki, generation)}
		return emitCobra(cmd, o.format, result)
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
	subject := pkix.Name{CommonName: o.pki + " Root CA", Organization: nonempty(o.subjectO), OrganizationalUnit: nonempty(o.subjectOU), Country: nonempty(o.subjectC), Province: nonempty(o.subjectST), Locality: nonempty(o.subjectL)}
	ski, err := pkicore.PublicKeyID(key.Public())
	if err != nil {
		return operational(err)
	}

	template := &x509.Certificate{SerialNumber: serialNumber, Subject: subject, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, o.days), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: ski}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return operational(err)
	}

	keyBytes, err := pkicore.MarshalPrivateKey(key, pass)
	if err != nil {
		return operational(err)
	}

	activeCert := certPEM(der)
	if err = write(filepath.Join(stage, "certs", "root.crt"), activeCert, 0644, false); err != nil {
		return operational(err)
	}
	if err = write(filepath.Join(stage, "private", "root.key"), keyBytes, 0600, false); err != nil {
		return operational(err)
	}

	bundle := append([]byte{}, activeCert...)
	bundle = append(bundle, previousBundle...)
	if err = write(filepath.Join(stage, "certs", "trust-bundle.crt"), bundle, 0644, false); err != nil {
		return operational(err)
	}

	trust := make([]uint64, 0, generation)
	for n := generation; n >= 1; n-- {
		trust = append(trust, n)
	}

	state := rootMetadata{SchemaVersion: storageSchemaVersion, ActiveGeneration: generation, TrustGenerations: trust}
	if operation == "rotate" {
		state.Rotation = new(rootRotation{From: generation - 1, To: generation, Phase: "migrating", StartedAt: now})
	}

	metadataBytes, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return operational(err)
	}
	if err = write(filepath.Join(stage, "metadata.json"), append(metadataBytes, '\n'), 0644, false); err != nil {
		return operational(err)
	}
	if err = commitObject(dir, stage, operation); err != nil {
		return operational(err)
	}

	result := output{Operation: operation, Type: "root", PKI: o.pki, Certificate: filepath.Join(dir, "certs", "root.crt"), PrivateKey: filepath.Join(dir, "private", "root.key"), Serial: strings.ToUpper(serialNumber.Text(16)), NotAfter: template.NotAfter.Format(time.RFC3339)}
	return emitCobra(cmd, o.format, result)
}

func emitCobra(cmd *cobra.Command, format string, value output) error {
	if format == "json" {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return operational(err)
		}

		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	}
	if len(value.Message) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), value.Message)
		return nil
	}
	if len(value.Certificate) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "certificate:", value.Certificate)
	}
	if len(value.PrivateKey) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "private key:", value.PrivateKey)
	}
	if len(value.Chain) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "chain:", value.Chain)
	}
	if len(value.FullChain) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "full chain:", value.FullChain)
	}
	if len(value.PKCS12) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "PKCS#12:", value.PKCS12)
	}
	if len(value.Serial) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "serial:", value.Serial)
	}
	if len(value.NotAfter) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "not after:", value.NotAfter)
	}

	return nil
}
