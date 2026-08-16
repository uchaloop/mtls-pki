package mtlspki

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uchaloop/mtls-pki/internal/apperr"
	storagecore "github.com/uchaloop/mtls-pki/internal/storage"
)

func usageError(format string, args ...any) error { return apperr.Make(apperr.Usage, format, args...) }

func operational(err error) error {
	if err == nil {
		return nil
	}

	return &apperr.Error{Code: apperr.Operational, Err: err}
}

func validateFormat(value string) error {
	if value != "text" && value != "json" {
		return usageError("--output must be text or json")
	}

	return nil
}

func sharedLock(root, pki string) (*storagecore.Lock, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lock, err := storagecore.Acquire(ctx, filepath.Join(root, pki), true)
	if err != nil {
		return nil, operational(err)
	}
	if hasPendingTransaction(filepath.Join(root, pki)) {
		_ = lock.Close()
		return nil, operational(fmt.Errorf("PKI has a pending transaction; run a mutating command to recover it"))
	}

	return lock, nil
}

func makeInspectCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{Use: "inspect CERT", Short: "Inspect a certificate", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFormat(format); err != nil {
			return err
		}

		cert, err := parseCert(args[0])
		if err != nil {
			return operational(err)
		}

		value := map[string]any{"subject": cert.Subject.String(), "issuer": cert.Issuer.String(), "serial": strings.ToUpper(cert.SerialNumber.Text(16)), "notBefore": cert.NotBefore, "notAfter": cert.NotAfter, "dns": cert.DNSNames, "ip": cert.IPAddresses, "uri": cert.URIs, "isCA": cert.IsCA, "keyUsage": cert.KeyUsage, "extendedKeyUsage": cert.ExtKeyUsage, "issuingCertificateURL": cert.IssuingCertificateURL, "crlDistributionPoints": cert.CRLDistributionPoints, "ocspServer": cert.OCSPServer, "sha256Fingerprint": fingerprint(cert)}
		if format == "json" {
			b, _ := json.MarshalIndent(value, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(b))
			return nil
		}

		fmt.Fprintf(cmd.OutOrStdout(), "subject: %s\nissuer: %s\nserial: %s\nnot before: %s\nnot after: %s\nsha256 fingerprint: %s\n", cert.Subject, cert.Issuer, strings.ToUpper(cert.SerialNumber.Text(16)), cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), fingerprint(cert))
		return nil
	}}

	cmd.Flags().StringVarP(&format, "output", "o", "text", "output format: text or json")
	return cmd
}

func makeVerifyCommand() *cobra.Command {
	var ca, issuer, purpose, hostname, crlPath, format string
	var renew time.Duration
	cmd := &cobra.Command{Use: "verify CERT", Short: "Verify a certificate", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if len(ca) == 0 {
			return usageError("--ca is required")
		}
		if err := validateFormat(format); err != nil {
			return err
		}
		if len(purpose) > 0 && purpose != "server" && purpose != "client" {
			return usageError("--purpose must be server or client")
		}
		if renew < 0 {
			return usageError("--renew-before cannot be negative")
		}

		leaf, err := parseCert(args[0])
		if err != nil {
			return operational(err)
		}

		rootCerts, err := parseCerts(ca)
		if err != nil {
			return operational(err)
		}

		roots, inter := x509.NewCertPool(), x509.NewCertPool()
		for _, cert := range rootCerts {
			roots.AddCert(cert)
		}

		var issuerCerts []*x509.Certificate
		if len(issuer) > 0 {
			issuerCerts, err = parseCerts(issuer)
			if err != nil {
				return operational(err)
			}

			for _, cert := range issuerCerts {
				inter.AddCert(cert)
			}
		}

		ku := x509.ExtKeyUsageAny
		if purpose == "server" {
			ku = x509.ExtKeyUsageServerAuth
		}
		if purpose == "client" {
			ku = x509.ExtKeyUsageClientAuth
		}
		chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: hostname, KeyUsages: []x509.ExtKeyUsage{ku}})
		if err != nil {
			return &apperr.Error{Code: apperr.Verification, Err: err}
		}
		if len(crlPath) > 0 {
			if len(issuerCerts) == 0 {
				return usageError("--crl requires --untrusted")
			}

			data, err := os.ReadFile(crlPath)
			if err != nil {
				return operational(err)
			}

			block, _ := pem.Decode(data)
			if block == nil {
				return operational(fmt.Errorf("invalid CRL PEM"))
			}

			rl, err := x509.ParseRevocationList(block.Bytes)
			if err != nil {
				return operational(err)
			}

			if !crlMatchesVerifiedChain(rl, chains) {
				return apperr.Make(apperr.Verification, "CRL signature does not match the certificate issuer")
			}

			now := time.Now()
			if now.Before(rl.ThisUpdate) || now.After(rl.NextUpdate) {
				return apperr.Make(apperr.Verification, "CRL is outside its validity window")
			}

			for _, entry := range rl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
					return apperr.Make(apperr.Revoked, "certificate is revoked")
				}
			}
		}
		if renew > 0 && time.Now().Add(renew).After(leaf.NotAfter) {
			return apperr.Make(apperr.Renewal, "certificate is inside renewal window")
		}
		if format == "json" {
			b, _ := json.Marshal(map[string]any{"operation": "verify", "certificate": args[0], "status": "valid", "notAfter": leaf.NotAfter})
			fmt.Fprintln(cmd.OutOrStdout(), string(b))
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), args[0]+": OK")
		}

		return nil
	}}

	cmd.Flags().StringVarP(&ca, "ca", "C", "", "Root CA certificate or bundle")
	cmd.Flags().StringVar(&issuer, "untrusted", "", "issuer certificate or bundle")
	cmd.Flags().StringVar(&purpose, "purpose", "", "certificate purpose: server or client")
	cmd.Flags().StringVarP(&hostname, "hostname", "H", "", "DNS hostname")
	cmd.Flags().StringVar(&crlPath, "crl", "", "issuer CRL")
	cmd.Flags().DurationVar(&renew, "renew-before", 0, "fail when expiry is within duration")
	cmd.Flags().StringVarP(&format, "output", "o", "text", "output format: text or json")
	return cmd
}

func crlMatchesVerifiedChain(
	crl *x509.RevocationList,
	chains [][]*x509.Certificate,
) bool {
	for _, chain := range chains {
		if len(chain) < 2 {
			continue
		}

		if crl.CheckSignatureFrom(chain[1]) == nil {
			return true
		}
	}

	return false
}

type listOptions struct {
	root, pki, format, typ, issuer, status, name string
	expiringWithin                               time.Duration
	expired                                      bool
}

func makeListCommand() *cobra.Command {
	o := &listOptions{}
	cmd := &cobra.Command{Use: "list", Short: "List issued certificates", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateCLIName(o.pki, "pki"); err != nil {
			return err
		}
		if err := validateFormat(o.format); err != nil {
			return err
		}
		if len(o.typ) > 0 && o.typ != "server" && o.typ != "client" {
			return usageError("--type must be server or client")
		}
		if len(o.status) > 0 && o.status != "valid" && o.status != "revoked" && o.status != "superseded" {
			return usageError("invalid --status")
		}
		if o.expiringWithin < 0 {
			return usageError("--expiring-within cannot be negative")
		}
		if o.expired && o.expiringWithin > 0 {
			return usageError("--expired and --expiring-within are mutually exclusive")
		}

		lock, err := sharedLock(o.root, o.pki)
		if err != nil {
			return err
		}
		defer lock.Close()

		records, err := readRecords(filepath.Join(o.root, o.pki, "index", "certificates.jsonl"))
		if err != nil {
			return operational(err)
		}

		now := time.Now().UTC()
		filtered := records[:0]
		for _, r := range records {
			if len(o.typ) > 0 && r.Type != o.typ || len(o.issuer) > 0 && r.Issuer != o.issuer || len(o.status) > 0 && r.Status != o.status || len(o.name) > 0 && r.Name != o.name {
				continue
			}
			if o.expired && r.NotAfter.After(now) {
				continue
			}
			if o.expiringWithin > 0 && (r.NotAfter.Before(now) || r.NotAfter.After(now.Add(o.expiringWithin))) {
				continue
			}

			filtered = append(filtered, r)
		}
		if o.format == "json" {
			b, _ := json.MarshalIndent(filtered, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(b))
			return nil
		}

		for _, r := range filtered {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n", r.Serial, r.Type, r.Name, r.Status, r.NotAfter.Format(time.RFC3339))
		}

		return nil
	}}

	f := cmd.Flags()
	f.StringVarP(&o.root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&o.pki, "pki", "p", "", "PKI name")
	f.StringVarP(&o.format, "output", "o", "text", "output format: text or json")
	f.StringVarP(&o.typ, "type", "t", "", "filter by type")
	f.StringVarP(&o.issuer, "issuer", "i", "", "filter by issuer")
	f.StringVarP(&o.status, "status", "s", "", "filter by status")
	f.StringVarP(&o.name, "name", "n", "", "filter by name")
	f.DurationVar(&o.expiringWithin, "expiring-within", 0, "filter by expiry window")
	f.BoolVar(&o.expired, "expired", false, "only expired certificates")
	return cmd
}

func makeIssuerListCommand() *cobra.Command { return makeIssuerReadCommand(false) }

func makeIssuerInspectCommand() *cobra.Command { return makeIssuerReadCommand(true) }

func makeIssuerReadCommand(inspect bool) *cobra.Command {
	var root, pki, name, format string
	use, short := "list", "List issuing CAs"
	if inspect {
		use = "inspect"
		short = "Inspect an issuing CA"
	}

	cmd := &cobra.Command{Use: use, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateCLIName(pki, "pki"); err != nil {
			return err
		}
		if inspect {
			if err := validateCLIName(name, "name"); err != nil {
				return err
			}
		}
		if err := validateFormat(format); err != nil {
			return err
		}

		lock, err := sharedLock(root, pki)
		if err != nil {
			return err
		}
		defer lock.Close()

		base := filepath.Join(root, pki, "issuers")
		if inspect {
			dir := filepath.Join(base, name)
			m, err := readIssuerMetadata(dir)
			if err != nil {
				return operational(err)
			}

			certPath, _ := activeIssuerPaths(dir, m)
			cert, err := parseCert(certPath)
			if err != nil {
				return operational(err)
			}

			v := map[string]any{"metadata": m, "subject": cert.Subject.String(), "issuer": cert.Issuer.String(), "serial": strings.ToUpper(cert.SerialNumber.Text(16)), "notBefore": cert.NotBefore, "notAfter": cert.NotAfter, "fingerprint": fingerprint(cert)}
			if format == "json" {
				out, _ := json.MarshalIndent(v, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "name: %s\ntype: %s\nstatus: %s\ngeneration: %d\nsubject: %s\nnot after: %s\n", m.Name, m.Type, m.Status, m.Generation, cert.Subject, cert.NotAfter.Format(time.RFC3339))
			}

			return nil
		}

		entries, err := os.ReadDir(base)
		if err != nil {
			return operational(err)
		}

		all := []metadata{}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			b, err := os.ReadFile(filepath.Join(base, entry.Name(), "metadata.json"))
			if err != nil {
				continue
			}

			var m metadata
			if json.Unmarshal(b, &m) == nil {
				all = append(all, m)
			}
		}

		slices.SortFunc(all, func(a, b metadata) int { return strings.Compare(a.Name, b.Name) })
		if format == "json" {
			out, _ := json.MarshalIndent(all, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		} else {
			for _, m := range all {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%d\n", m.Name, m.Type, m.Status, m.Generation)
			}
		}

		return nil
	}}

	f := cmd.Flags()
	f.StringVarP(&root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&pki, "pki", "p", "", "PKI name")
	f.StringVarP(&format, "output", "o", "text", "output format: text or json")
	if inspect {
		f.StringVarP(&name, "name", "n", "", "issuer name")
	}

	return cmd
}
