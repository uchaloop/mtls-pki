package mtlspki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	pkicore "github.com/uchaloop/mtls-pki/internal/pki"
	secretcore "github.com/uchaloop/mtls-pki/internal/secretinput"
)

type crlOptions struct {
	root, pki, issuer, passEnv, passFile, format string
	generation                                   uint64
	days                                         int
	passStdin                                    bool
}

func makeCRLGenerateCommand() *cobra.Command {
	o := &crlOptions{}
	cmd := &cobra.Command{Use: "generate", Short: "Generate an issuer CRL", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runCRLGenerate(cmd, o) }}
	f := cmd.Flags()
	f.StringVarP(&o.root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&o.pki, "pki", "p", "", "PKI name")
	f.StringVarP(&o.issuer, "issuer", "i", "", "issuer name")
	f.Uint64VarP(&o.generation, "generation", "g", 0, "issuer generation (default active)")
	f.IntVarP(&o.days, "days", "D", 7, "CRL validity days")
	f.StringVar(&o.passEnv, "issuer-pass-env", "", "issuer password environment variable")
	f.StringVar(&o.passFile, "issuer-pass-file", "", "issuer password file")
	f.BoolVar(&o.passStdin, "issuer-pass-stdin", false, "read issuer password from stdin")
	f.StringVarP(&o.format, "output", "o", "text", "output format: text or json")
	return cmd
}

func runCRLGenerate(cmd *cobra.Command, o *crlOptions) error {
	if err := validateCLIName(o.pki, "pki"); err != nil {
		return err
	}
	if err := validateCLIName(o.issuer, "issuer"); err != nil {
		return err
	}
	if o.days < 1 {
		return usageError("--days must be positive")
	}
	if err := validateFormat(o.format); err != nil {
		return err
	}
	if err := validatePasswordSource(o.passEnv, o.passFile, o.passStdin); err != nil {
		return usageError("%v", err)
	}

	lock, err := exclusiveLock(o.root, o.pki)
	if err != nil {
		return err
	}
	defer lock.Close()

	issuerBase := filepath.Join(o.root, o.pki, "issuers", o.issuer)
	metaBytes, err := os.ReadFile(filepath.Join(issuerBase, "metadata.json"))
	if err != nil {
		return operational(err)
	}

	var meta metadata
	if err = json.Unmarshal(metaBytes, &meta); err != nil {
		return operational(err)
	}

	generation := o.generation
	if generation == 0 {
		generation = meta.Generation
	}
	if generation == 0 {
		generation = 1
	}
	if generation > meta.Generation && meta.Generation != 0 {
		return usageError("issuer generation %d does not exist", generation)
	}

	generationBase := generationDir(issuerBase, generation)
	certPath := filepath.Join(generationBase, "certs", "issuer.crt")
	keyPath := filepath.Join(generationBase, "private", "issuer.key")
	if !exists(certPath) && generation == meta.Generation {
		certPath = filepath.Join(issuerBase, "certs", "issuer.crt")
		keyPath = filepath.Join(issuerBase, "private", "issuer.key")
	}

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

	records, err := readRecords(filepath.Join(o.root, o.pki, "index", "certificates.jsonl"))
	if err != nil {
		return operational(err)
	}

	revoked := []x509.RevocationListEntry{}
	for _, r := range records {
		recordGeneration := r.IssuerGeneration
		if recordGeneration == 0 {
			recordGeneration = 1
		}
		if r.Issuer != o.issuer || recordGeneration != generation || r.Status != "revoked" || r.RevokedAt == nil {
			continue
		}

		serial := new(big.Int)
		if _, ok := serial.SetString(r.Serial, 16); !ok {
			return operational(fmt.Errorf("bad serial %q in registry", r.Serial))
		}

		revoked = append(revoked, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: *r.RevokedAt, ReasonCode: reasonCode(r.Reason)})
	}

	crlDir := filepath.Join(generationBase, "crl")
	numberPath := filepath.Join(crlDir, "number")
	var number uint64
	if data, readErr := os.ReadFile(numberPath); readErr == nil {
		number, err = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			return operational(err)
		}
	} else if !os.IsNotExist(readErr) {
		return operational(readErr)
	}

	number++
	now := time.Now().UTC()
	next := now.AddDate(0, 0, o.days)
	if next.After(issuerCert.NotAfter) {
		return operational(fmt.Errorf("CRL NextUpdate exceeds issuer validity"))
	}

	tpl := &x509.RevocationList{SignatureAlgorithm: issuerCert.SignatureAlgorithm, RevokedCertificateEntries: revoked, Number: new(big.Int).SetUint64(number), ThisUpdate: now.Add(-5 * time.Minute), NextUpdate: next}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, issuerCert, issuerKey)
	if err != nil {
		return operational(err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	out := filepath.Join(crlDir, "issuer.crl")
	if err = write(out, encoded, 0644, true); err != nil {
		return operational(err)
	}
	if err = write(numberPath, []byte(strconv.FormatUint(number, 10)+"\n"), 0600, true); err != nil {
		return operational(err)
	}
	if generation == meta.Generation || (meta.Generation == 0 && generation == 1) {
		if err = write(filepath.Join(issuerBase, "crl", "issuer.crl"), encoded, 0644, true); err != nil {
			return operational(err)
		}
		if err = write(filepath.Join(issuerBase, "crl", "number"), []byte(strconv.FormatUint(number, 10)+"\n"), 0600, true); err != nil {
			return operational(err)
		}
	}
	if o.format == "json" {
		result, _ := json.Marshal(map[string]any{"operation": "crl-generate", "issuer": o.issuer, "generation": generation, "crl": out, "crlNumber": number, "revokedCertificates": len(revoked), "nextUpdate": next})
		fmt.Fprintln(cmd.OutOrStdout(), string(result))
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "CRL:", out)
	}

	return nil
}
