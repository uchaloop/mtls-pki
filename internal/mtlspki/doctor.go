package mtlspki

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uchaloop/mtls-pki/internal/apperr"
	pkicore "github.com/uchaloop/mtls-pki/internal/pki"
	secretcore "github.com/uchaloop/mtls-pki/internal/secretinput"
	storagecore "github.com/uchaloop/mtls-pki/internal/storage"
)

type doctorIssue struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
}

type doctorReport struct {
	Status       string        `json:"status"`
	PKI          string        `json:"pki"`
	Root         string        `json:"root"`
	CheckedAt    time.Time     `json:"checkedAt"`
	Roots        int           `json:"roots"`
	Issuers      int           `json:"issuers"`
	Certificates int           `json:"certificates"`
	CRLs         int           `json:"crls"`
	Issues       []doctorIssue `json:"issues"`
}

type doctor struct {
	base, pkiDir  string
	report        doctorReport
	roots         *x509.CertPool
	issuers       map[string]*x509.Certificate
	records       []record
	rootPass      []byte
	issuerPass    []byte
	hasRootPass   bool
	hasIssuerPass bool
}

func makeDoctorCommand() *cobra.Command {
	var root, pki, format, rootPassEnv, rootPassFile, issuerPassEnv, issuerPassFile string
	var rootPassStdin, issuerPassStdin bool
	cmd := &cobra.Command{Use: "doctor", Short: "Audit PKI consistency without modifying it", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateCLIName(pki, "pki"); err != nil {
			return err
		}
		if err := validateFormat(format); err != nil {
			return err
		}
		if rootPassStdin && issuerPassStdin {
			return usageError("stdin cannot provide Root and issuer passwords simultaneously")
		}
		if err := validatePasswordSource(rootPassEnv, rootPassFile, rootPassStdin); err != nil {
			return usageError("invalid Root password source: %v", err)
		}
		if err := validatePasswordSource(issuerPassEnv, issuerPassFile, issuerPassStdin); err != nil {
			return usageError("invalid issuer password source: %v", err)
		}

		rootPass, err := password(rootPassEnv, rootPassFile, rootPassStdin)
		if err != nil {
			return operational(err)
		}
		defer secretcore.Clear(rootPass)

		issuerPass, err := password(issuerPassEnv, issuerPassFile, issuerPassStdin)
		if err != nil {
			return operational(err)
		}
		defer secretcore.Clear(issuerPass)

		pkiDir := filepath.Join(root, pki)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		lock, err := storagecore.Acquire(ctx, pkiDir, true)
		if err != nil {
			return operational(err)
		}
		defer lock.Close()

		d := &doctor{base: root, pkiDir: pkiDir, roots: x509.NewCertPool(), issuers: make(map[string]*x509.Certificate), rootPass: rootPass, issuerPass: issuerPass, hasRootPass: len(rootPassEnv) > 0 || len(rootPassFile) > 0 || rootPassStdin, hasIssuerPass: len(issuerPassEnv) > 0 || len(issuerPassFile) > 0 || issuerPassStdin, report: doctorReport{Status: "healthy", PKI: pki, Root: pkiDir, CheckedAt: time.Now().UTC(), Issues: []doctorIssue{}}}
		d.run()
		if format == "json" {
			data, _ := json.MarshalIndent(d.report, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "PKI: %s\nstatus: %s\nchecked: %d root(s), %d issuer generation(s), %d certificate(s), %d CRL(s)\n", d.report.PKI, d.report.Status, d.report.Roots, d.report.Issuers, d.report.Certificates, d.report.CRLs)
			for _, issue := range d.report.Issues {
				location := ""
				if len(issue.Path) > 0 {
					location = " [" + issue.Path + "]"
				}

				fmt.Fprintf(cmd.OutOrStdout(), "%s %s%s: %s\n", strings.ToUpper(issue.Severity), issue.Code, location, issue.Message)
			}
		}
		if d.errorCount() > 0 {
			return apperr.Make(apperr.Verification, "doctor found %d error(s)", d.errorCount())
		}

		return nil
	}}

	f := cmd.Flags()
	f.StringVarP(&root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&pki, "pki", "p", "", "PKI name")
	f.StringVarP(&format, "output", "o", "text", "output format: text or json")
	f.StringVar(&rootPassEnv, "root-pass-env", "", "Root key password environment variable")
	f.StringVar(&rootPassFile, "root-pass-file", "", "Root key password file")
	f.BoolVar(&rootPassStdin, "root-pass-stdin", false, "read Root key password from stdin")
	f.StringVar(&issuerPassEnv, "issuer-pass-env", "", "issuer key password environment variable")
	f.StringVar(&issuerPassFile, "issuer-pass-file", "", "issuer key password file")
	f.BoolVar(&issuerPassStdin, "issuer-pass-stdin", false, "read issuer key password from stdin")
	return cmd
}

func (d *doctor) run() {
	if hasPendingTransaction(d.pkiDir) {
		d.add("error", "pending_transaction", transactionPath(d.pkiDir), "an interrupted leaf transaction requires recovery")
	}

	d.checkPrivateMaterialPermissions()
	d.checkRoots()
	d.checkIssuers()
	d.checkRegistry()
	d.checkOrphans()
	d.checkCRLs()
	if d.errorCount() > 0 {
		d.report.Status = "unhealthy"
	} else if len(d.report.Issues) > 0 {
		d.report.Status = "warning"
	}
}

func (d *doctor) checkRoots() {
	path := filepath.Join(d.pkiDir, "root", "certs", "trust-bundle.crt")
	certs, err := parseCerts(path)
	if err != nil {
		d.add("error", "root_bundle", path, err.Error())
		return
	}

	for _, cert := range certs {
		d.report.Roots++
		if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
			d.add("error", "invalid_root", path, "certificate is not a self-signed CA")
		}
		if time.Now().After(cert.NotAfter) {
			d.add("error", "expired_root", path, "Root CA has expired")
		}

		d.roots.AddCert(cert)
	}

	d.checkKey(filepath.Join(d.pkiDir, "root", "certs", "root.crt"), filepath.Join(d.pkiDir, "root", "private", "root.key"), d.rootPass, d.hasRootPass)
}

func (d *doctor) checkIssuers() {
	base := filepath.Join(d.pkiDir, "issuers")
	entries, err := os.ReadDir(base)
	if err != nil {
		d.add("error", "issuers_directory", base, err.Error())
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dir := filepath.Join(base, entry.Name())
		meta, err := readIssuerMetadata(dir)
		if err != nil {
			d.add("error", "issuer_metadata", filepath.Join(dir, "metadata.json"), err.Error())
			continue
		}
		if meta.Name != entry.Name() || (meta.Type != "server" && meta.Type != "client") || (meta.Status != "active" && meta.Status != "retired") || meta.Generation == 0 {
			d.add("error", "issuer_metadata", filepath.Join(dir, "metadata.json"), "invalid issuer name, type, status or generation")
		}

		for generation := uint64(1); generation <= meta.Generation; generation++ {
			certPath, keyPath := issuerGenerationPaths(dir, generation)
			cert, err := parseCert(certPath)
			if err != nil {
				d.add("error", "issuer_certificate", certPath, err.Error())
				continue
			}

			d.report.Issuers++
			if !cert.IsCA {
				d.add("error", "issuer_constraints", certPath, "issuer certificate is not a CA")
			}
			if _, err = cert.Verify(x509.VerifyOptions{Roots: d.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				d.add("error", "issuer_chain", certPath, err.Error())
			}

			d.checkKey(certPath, keyPath, d.issuerPass, d.hasIssuerPass)
			d.issuers[issuerKey(entry.Name(), generation)] = cert
		}

		activeCert, _ := activeIssuerPaths(dir, meta)
		generationCert, _ := issuerGenerationPaths(dir, meta.Generation)
		if !sameFileContents(activeCert, generationCert) {
			d.add("error", "issuer_projection", activeCert, "active certificate differs from its generation")
		}
	}
}

func (d *doctor) checkRegistry() {
	path := filepath.Join(d.pkiDir, "index", "certificates.jsonl")
	records, err := readRecords(path)
	if err != nil {
		d.add("error", "registry", path, err.Error())
		return
	}

	d.records = records
	seen := make(map[string]bool)
	for _, record := range records {
		d.report.Certificates++
		if seen[record.Serial] {
			d.add("error", "duplicate_serial", path, "duplicate serial "+record.Serial)
		}

		seen[record.Serial] = true
		if record.Type != "server" && record.Type != "client" || record.Status != "valid" && record.Status != "revoked" && record.Status != "superseded" {
			d.add("error", "registry_record", path, "invalid type or status for serial "+record.Serial)
			continue
		}

		cert, err := parseCert(record.Certificate)
		if err != nil {
			d.add("error", "leaf_certificate", record.Certificate, err.Error())
			continue
		}
		if strings.ToUpper(cert.SerialNumber.Text(16)) != record.Serial || cert.NotAfter.Unix() != record.NotAfter.Unix() {
			d.add("error", "registry_mismatch", record.Certificate, "certificate serial or expiry differs from registry")
		}

		issuer := d.issuers[issuerKey(record.Issuer, record.IssuerGeneration)]
		if issuer == nil {
			d.add("error", "missing_issuer", record.Certificate, fmt.Sprintf("issuer %s generation %d is unavailable", record.Issuer, record.IssuerGeneration))
			continue
		}

		pool := x509.NewCertPool()
		pool.AddCert(issuer)
		usage := x509.ExtKeyUsageServerAuth
		if record.Type == "client" {
			usage = x509.ExtKeyUsageClientAuth
		}
		if _, err = cert.Verify(x509.VerifyOptions{Roots: d.roots, Intermediates: pool, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			d.add("error", "leaf_chain", record.Certificate, err.Error())
		}
	}
}

func (d *doctor) checkOrphans() {
	registered := make(map[string]bool, len(d.records))
	for _, record := range d.records {
		absolute, err := filepath.Abs(record.Certificate)
		if err == nil {
			registered[absolute] = true
		}
	}

	_ = filepath.WalkDir(filepath.Join(d.pkiDir, "certificates"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			d.add("error", "certificate_walk", path, walkErr.Error())
			return nil
		}
		if entry.IsDir() || entry.Name() != "server.crt" && entry.Name() != "client.crt" {
			return nil
		}

		absolute, err := filepath.Abs(path)
		if err == nil && !registered[absolute] {
			d.add("error", "orphan_certificate", path, "certificate exists on disk but is absent from registry")
		}

		return nil
	})
}

func (d *doctor) checkCRLs() {
	_ = filepath.WalkDir(filepath.Join(d.pkiDir, "issuers"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			d.add("error", "crl_walk", path, walkErr.Error())
			return nil
		}
		if entry.IsDir() || filepath.Ext(path) != ".crl" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			d.add("error", "crl", path, err.Error())
			return nil
		}

		block, _ := pem.Decode(data)
		if block == nil {
			d.add("error", "crl", path, "invalid PEM")
			return nil
		}

		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			d.add("error", "crl", path, err.Error())
			return nil
		}

		d.report.CRLs++
		generationDir := filepath.Dir(filepath.Dir(path))
		generation, parseErr := strconv.ParseUint(filepath.Base(generationDir), 10, 64)
		issuerName := filepath.Base(filepath.Dir(filepath.Dir(generationDir)))
		if parseErr != nil {
			issuerDir := generationDir
			issuerName = filepath.Base(issuerDir)
			meta, metaErr := readIssuerMetadata(issuerDir)
			if metaErr == nil {
				generation = meta.Generation
				parseErr = nil
			}
		}

		issuer := d.issuers[issuerKey(issuerName, generation)]
		if parseErr != nil || issuer == nil || crl.CheckSignatureFrom(issuer) != nil {
			d.add("error", "crl_signature", path, "signature does not match the CRL issuer generation")
		}

		numberPath := filepath.Join(filepath.Dir(path), "number")
		numberData, numberErr := os.ReadFile(numberPath)
		if numberErr != nil || crl.Number == nil || strings.TrimSpace(string(numberData)) != crl.Number.String() {
			d.add("error", "crl_number", numberPath, "persisted CRL number does not match the CRL")
		}
		if time.Now().After(crl.NextUpdate) {
			d.add("error", "expired_crl", path, "CRL has expired")
		}

		return nil
	})
}

func (d *doctor) checkKey(certPath, keyPath string, pass []byte, hasPass bool) {
	cert, err := parseCert(certPath)
	if err != nil {
		d.add("error", "certificate", certPath, err.Error())
		return
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		d.add("error", "private_key", keyPath, err.Error())
		return
	}

	block, _ := pem.Decode(data)
	if block == nil {
		d.add("error", "private_key", keyPath, "invalid PEM")
		return
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" || x509.IsEncryptedPEMBlock(block) {
		if !hasPass {
			d.add("warning", "encrypted_key_skipped", keyPath, "key matching requires a password and was skipped")
			return
		}
	}

	key, err := pkicore.ParsePrivateKey(data, pass)
	if err != nil {
		d.add("error", "private_key", keyPath, err.Error())
		return
	}
	if err = pkicore.MatchCertificateKey(cert, key); err != nil {
		d.add("error", "key_mismatch", keyPath, err.Error())
	}
}

func (d *doctor) checkPrivateMaterialPermissions() {
	if runtime.GOOS == "windows" {
		return
	}

	_ = filepath.WalkDir(d.pkiDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			d.add("error", "private_material_walk", path, walkErr.Error())
			return nil
		}
		if entry.IsDir() || filepath.Ext(path) != ".key" && filepath.Ext(path) != ".p12" {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			d.add("error", "private_material_permissions", path, err.Error())
			return nil
		}
		if !securePrivateKeyPermissions(info.Mode()) {
			d.add(
				"error",
				"private_material_permissions",
				path,
				fmt.Sprintf("private material permissions %04o expose it to group or other users", info.Mode().Perm()),
			)
		}

		return nil
	})
}

func securePrivateKeyPermissions(mode os.FileMode) bool {
	return mode.Perm()&0077 == 0
}

func (d *doctor) add(severity, code, path, message string) {
	d.report.Issues = append(d.report.Issues, doctorIssue{Severity: severity, Code: code, Path: path, Message: message})
	slices.SortStableFunc(d.report.Issues, func(a, b doctorIssue) int { return strings.Compare(a.Path, b.Path) })
}

func (d *doctor) errorCount() int {
	count := 0
	for _, issue := range d.report.Issues {
		if issue.Severity == "error" {
			count++
		}
	}

	return count
}

func issuerKey(name string, generation uint64) string { return fmt.Sprintf("%s/%d", name, generation) }

func sameFileContents(left, right string) bool {
	a, err := os.ReadFile(left)
	if err != nil {
		return false
	}

	b, err := os.ReadFile(right)
	return err == nil && string(a) == string(b)
}
