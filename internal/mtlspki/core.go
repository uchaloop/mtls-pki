package mtlspki

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	identitycore "github.com/uchaloop/mtls-pki/internal/identity"
	pkicore "github.com/uchaloop/mtls-pki/internal/pki"
	registrycore "github.com/uchaloop/mtls-pki/internal/registry"
	secretcore "github.com/uchaloop/mtls-pki/internal/secretinput"
	storagecore "github.com/uchaloop/mtls-pki/internal/storage"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const storageSchemaVersion = 1

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// buildVersion reports the metadata stamped by a release build and falls back to the
// module and VCS information that the toolchain embeds into `go install` binaries.
func buildVersion() string {
	version, commit, date := Version, Commit, BuildDate

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
	}

	if version == "dev" && len(info.Main.Version) > 0 {
		version = info.Main.Version
	}

	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if commit == "unknown" {
				commit = setting.Value
			}
		case "vcs.time":
			if date == "unknown" {
				date = setting.Value
			}
		}
	}

	return fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
}

type record = registrycore.Certificate

type metadata struct {
	SchemaVersion  int       `json:"schemaVersion"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	CreatedAt      time.Time `json:"createdAt"`
	Status         string    `json:"status"`
	Generation     uint64    `json:"generation,omitempty"`
	RootGeneration uint64    `json:"rootGeneration,omitempty"`
	Serial         string    `json:"serial,omitempty"`
	Fingerprint    string    `json:"fingerprint,omitempty"`
}

type rootMetadata struct {
	SchemaVersion    int           `json:"schemaVersion"`
	ActiveGeneration uint64        `json:"activeGeneration"`
	TrustGenerations []uint64      `json:"trustGenerations"`
	Rotation         *rootRotation `json:"rotation,omitempty"`
}

type rootRotation struct {
	From      uint64    `json:"from"`
	To        uint64    `json:"to"`
	Phase     string    `json:"phase"`
	StartedAt time.Time `json:"startedAt"`
}

type profile struct {
	RootDays   int    `json:"rootDays"`
	IssuerDays int    `json:"issuerDays"`
	ServerDays int    `json:"serverDays"`
	ClientDays int    `json:"clientDays"`
	Algorithm  string `json:"algorithm"`
	Curve      string `json:"curve"`
	RSABits    int    `json:"rsaBits"`
}

type output struct {
	Operation       string   `json:"operation,omitempty"`
	Type            string   `json:"type"`
	PKI             string   `json:"pki,omitempty"`
	Issuer          string   `json:"issuer,omitempty"`
	Name            string   `json:"name,omitempty"`
	Algorithm       string   `json:"algorithm,omitempty"`
	Curve           string   `json:"curve,omitempty"`
	RSABits         int      `json:"rsaBits,omitempty"`
	ValidityDays    int      `json:"validityDays,omitempty"`
	DNS             []string `json:"dns,omitempty"`
	IP              []string `json:"ip,omitempty"`
	URI             []string `json:"uri,omitempty"`
	OutputDirectory string   `json:"outputDirectory,omitempty"`
	Certificate     string   `json:"certificate,omitempty"`
	PrivateKey      string   `json:"privateKey,omitempty"`
	Chain           string   `json:"chain,omitempty"`
	FullChain       string   `json:"fullchain,omitempty"`
	PKCS12          string   `json:"pkcs12,omitempty"`
	Serial          string   `json:"serial,omitempty"`
	NotAfter        string   `json:"notAfter,omitempty"`
	Message         string   `json:"message,omitempty"`
}

func exists(p string) bool {
	_, err := os.Stat(p)

	return err == nil
}

func write(path string, data []byte, mode os.FileMode, force bool) error {
	if exists(path) && !force {
		return fmt.Errorf("%s exists; use --force", path)
	}

	return storagecore.WriteAtomic(path, data, mode, force)
}

func copyFile(source, target string, mode os.FileMode) error {
	b, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	return write(target, b, mode, false)
}

func generationDir(base string, generation uint64) string {
	return filepath.Join(base, "generations", fmt.Sprintf("%06d", generation))
}

func readIssuerMetadata(dir string) (metadata, error) {
	var m metadata
	b, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return m, err
	}
	if err = json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if err = validateSchemaVersion(m.SchemaVersion); err != nil {
		return m, err
	}
	if m.SchemaVersion == 0 {
		m.SchemaVersion = storageSchemaVersion
	}
	if m.Generation == 0 {
		m.Generation = 1
	}

	return m, nil
}

func validateSchemaVersion(version int) error {
	if version < 0 || version > storageSchemaVersion {
		return fmt.Errorf("unsupported storage schema version %d (maximum %d)", version, storageSchemaVersion)
	}

	return nil
}

func issuerGenerationPaths(dir string, generation uint64) (cert, key string) {
	base := generationDir(dir, generation)
	return filepath.Join(base, "certs", "issuer.crt"), filepath.Join(base, "private", "issuer.key")
}

func activeIssuerPaths(dir string, m metadata) (cert, key string) {
	cert, key = issuerGenerationPaths(dir, m.Generation)
	if exists(cert) && exists(key) {
		return cert, key
	}

	return filepath.Join(dir, "certs", "issuer.crt"), filepath.Join(dir, "private", "issuer.key")
}

func beginObject(target, op string) (string, func(), error) {
	present := exists(target)
	switch op {
	case "create", "issue":
		if present {
			return "", nil, fmt.Errorf("%s already exists", target)
		}
	case "rotate", "renew":
		if !present {
			return "", nil, fmt.Errorf("%s does not exist", target)
		}
	default:
		return "", nil, fmt.Errorf("invalid operation %s", op)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return "", nil, err
	}

	stage, err := os.MkdirTemp(filepath.Dir(target), "."+filepath.Base(target)+".stage-")
	if err != nil {
		return "", nil, err
	}

	return stage, func() { _ = os.RemoveAll(stage) }, nil
}

func validateObjectState(target, op string) error {
	present := exists(target)
	if (op == "create" || op == "issue") && present {
		return fmt.Errorf("%s already exists", target)
	}
	if (op == "rotate" || op == "renew") && !present {
		return fmt.Errorf("%s does not exist", target)
	}

	return nil
}

func commitObject(target, stage, op string) error {
	if op == "create" || op == "issue" {
		return os.Rename(stage, target)
	}

	history := filepath.Join(filepath.Dir(target), "history", filepath.Base(target)+"-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.MkdirAll(filepath.Dir(history), 0700); err != nil {
		return err
	}
	if err := os.Rename(target, history); err != nil {
		return err
	}
	if err := os.Rename(stage, target); err != nil {
		_ = os.Rename(history, target)
		return err
	}

	return nil
}

func commitIssuerGeneration(target, stage string, generation uint64) error {
	if !exists(filepath.Join(target, "generations")) {
		legacy := generationDir(target, 1)
		if err := copyFile(filepath.Join(target, "certs", "issuer.crt"), filepath.Join(legacy, "certs", "issuer.crt"), 0644); err != nil {
			return err
		}
		if err := copyFile(filepath.Join(target, "private", "issuer.key"), filepath.Join(legacy, "private", "issuer.key"), 0600); err != nil {
			return err
		}
	}

	stagedGeneration := generationDir(stage, generation)
	finalGeneration := generationDir(target, generation)
	if exists(finalGeneration) {
		return fmt.Errorf("issuer generation %d already exists", generation)
	}
	if err := os.MkdirAll(filepath.Dir(finalGeneration), 0700); err != nil {
		return err
	}
	if err := os.Rename(stagedGeneration, finalGeneration); err != nil {
		return err
	}

	metadataBytes, err := os.ReadFile(filepath.Join(stage, "metadata.json"))
	if err != nil {
		return err
	}
	if err = write(filepath.Join(target, "metadata.json"), metadataBytes, 0644, true); err != nil {
		return err
	}

	certPath, keyPath := issuerGenerationPaths(target, generation)
	if err = copyFileReplace(certPath, filepath.Join(target, "certs", "issuer.crt"), 0644); err != nil {
		return err
	}
	if err = copyFileReplace(keyPath, filepath.Join(target, "private", "issuer.key"), 0600); err != nil {
		return err
	}

	return nil
}

func copyFileReplace(source, target string, mode os.FileMode) error {
	b, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	return write(target, b, mode, true)
}

func hasEntries(dir string) bool {
	entries, e := os.ReadDir(dir)

	return e == nil && len(entries) > 0
}

func serial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, e := rand.Int(rand.Reader, limit)
		if e != nil {
			return nil, e
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

func parseCert(path string) (*x509.Certificate, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}

	p, _ := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate: %s", path)
	}

	return x509.ParseCertificate(p.Bytes)
}

func parseCerts(path string) ([]*x509.Certificate, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}

	var certs []*x509.Certificate
	for len(b) > 0 {
		block, rest := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("invalid certificate bundle: %s", path)
		}

		b = rest
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("certificate bundle is empty: %s", path)
	}

	return certs, nil
}

func issuerRoot(rootDir string, issuer *x509.Certificate) (*x509.Certificate, error) {
	bundle := filepath.Join(rootDir, "certs", "trust-bundle.crt")
	if !exists(bundle) {
		bundle = filepath.Join(rootDir, "certs", "root.crt")
	}

	roots, e := parseCerts(bundle)
	if e != nil {
		return nil, e
	}

	for _, root := range roots {
		if pkicore.VerifyIssuer(root, issuer) == nil {
			return root, nil
		}
	}

	return nil, errors.New("issuer is not signed by a trusted Root generation")
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

func password(env, file string, stdin bool) ([]byte, error) {
	return (secretcore.Source{Env: env, File: file, Stdin: stdin}).Read(os.Stdin, os.Stderr)
}

func validatePasswordSource(env, file string, stdin bool) error {
	n := 0
	if len(env) > 0 {
		n++
	}
	if len(file) > 0 {
		n++
	}
	if stdin {
		n++
	}
	if n > 1 {
		return errors.New("choose one password source")
	}
	if len(env) > 0 {
		if _, ok := os.LookupEnv(env); !ok {
			return fmt.Errorf("environment variable %s is not set", env)
		}
	}
	if len(file) > 0 {
		if _, e := os.Stat(file); e != nil {
			return e
		}
	}

	return nil
}

func validateCAKeyProtection(password []byte, allowUnencrypted bool) error {
	if len(password) == 0 && !allowUnencrypted {
		return usageError(
			"CA private key password is required; use a password source or explicitly pass --allow-unencrypted-key",
		)
	}

	return nil
}

func parseKey(path string, pass []byte) (crypto.Signer, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}

	return pkicore.ParsePrivateKey(b, pass)
}

func genKey(alg string, bits int, curve string) (crypto.Signer, error) {
	switch alg {
	case "rsa":
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return nil, errors.New("rsa bits must be 2048, 3072 or 4096")
		}

		return rsa.GenerateKey(rand.Reader, bits)
	case "ecdsa":
		var c elliptic.Curve
		switch curve {
		case "P-256", "prime256v1", "":
			c = elliptic.P256()
		case "P-384", "secp384r1":
			c = elliptic.P384()
		default:
			return nil, errors.New("curve must be P-256 or P-384")
		}

		return ecdsa.GenerateKey(c, rand.Reader)
	default:
		return nil, errors.New("algorithm must be rsa or ecdsa")
	}
}

func baseProfile() profile { return profile{3650, 1825, 180, 365, "rsa", "P-256", 3072} }

func loadProfile(path string) (profile, error) {
	p := baseProfile()
	if len(path) == 0 {
		return p, nil
	}

	b, e := os.ReadFile(path)
	if e != nil {
		return p, e
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	e = dec.Decode(&p)
	if e != nil {
		return p, e
	}
	if dec.More() {
		return p, errors.New("profile must contain one JSON object")
	}

	return validateProfile(p)
}

func envInt(name string, current int) (int, error) {
	if v := os.Getenv(name); len(v) > 0 {
		var n int
		if _, e := fmt.Sscanf(v, "%d", &n); e != nil || n < 1 {
			return 0, fmt.Errorf("invalid %s=%q: expected positive integer", name, v)
		}

		return n, nil
	}

	return current, nil
}

func applyEnv(p profile) (profile, error) {
	var e error
	if p.RootDays, e = envInt("MTLS_PKI_ROOT_DAYS", p.RootDays); e != nil {
		return p, e
	}
	if p.IssuerDays, e = envInt("MTLS_PKI_ISSUER_DAYS", p.IssuerDays); e != nil {
		return p, e
	}
	if p.ServerDays, e = envInt("MTLS_PKI_SERVER_DAYS", p.ServerDays); e != nil {
		return p, e
	}
	if p.ClientDays, e = envInt("MTLS_PKI_CLIENT_DAYS", p.ClientDays); e != nil {
		return p, e
	}
	if v := os.Getenv("MTLS_PKI_KEY_ALGORITHM"); len(v) > 0 {
		p.Algorithm = v
	}
	if p.RSABits, e = envInt("MTLS_PKI_RSA_BITS", p.RSABits); e != nil {
		return p, e
	}
	if v := os.Getenv("MTLS_PKI_ECDSA_CURVE"); len(v) > 0 {
		p.Curve = v
	}

	return validateProfile(p)
}

func validateProfile(p profile) (profile, error) {
	if p.RootDays < 1 || p.IssuerDays < 1 || p.ServerDays < 1 || p.ClientDays < 1 {
		return p, errors.New("all validity values must be positive")
	}
	if p.Algorithm != "rsa" && p.Algorithm != "ecdsa" {
		return p, errors.New("algorithm must be rsa or ecdsa")
	}
	if p.RSABits != 2048 && p.RSABits != 3072 && p.RSABits != 4096 {
		return p, errors.New("rsaBits must be 2048, 3072 or 4096")
	}
	if p.Curve != "P-256" && p.Curve != "P-384" && p.Curve != "prime256v1" && p.Curve != "secp384r1" {
		return p, errors.New("curve must be P-256 or P-384")
	}

	return p, nil
}

func checkParent(parent *x509.Certificate, days int) error {
	if days < 1 {
		return errors.New("days must be positive")
	}
	if time.Now().UTC().Add(time.Duration(days)*24*time.Hour + 24*time.Hour).After(parent.NotAfter) {
		return errors.New("requested validity exceeds parent CA validity (including one-day safety margin)")
	}

	return nil
}

func keyUsageFor(typ, alg string) x509.KeyUsage {
	if typ == "server" && alg == "rsa" {
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	return x509.KeyUsageDigitalSignature
}

func validateKeyOptions(alg string, bits int, curve string) error {
	switch alg {
	case "rsa":
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return errors.New("rsa bits must be 2048, 3072 or 4096")
		}
	case "ecdsa":
		if curve != "P-256" && curve != "P-384" && curve != "prime256v1" && curve != "secp384r1" {
			return errors.New("curve must be P-256 or P-384")
		}
	default:
		return errors.New("algorithm must be rsa or ecdsa")
	}

	return nil
}

func nonempty(v string) []string {
	if len(v) == 0 {
		return nil
	}

	return []string{v}
}

func validCountry(v string) bool {
	if len(v) != 2 {
		return false
	}

	for _, r := range v {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}

	return true
}

func makePKCS12(key, cert, chain, out string, pass []byte) error {
	signer, e := parseKey(key, nil)
	if e != nil {
		return e
	}

	leaf, e := parseCert(cert)
	if e != nil {
		return e
	}

	caCerts, e := parseCerts(chain)
	if e != nil {
		return e
	}

	pfx, e := pkcs12.Modern2023.Encode(signer, leaf, caCerts, string(pass))
	if e != nil {
		return fmt.Errorf("encode PKCS#12: %w", e)
	}

	return write(out, pfx, 0600, false)
}

func unique(in []string) []string {
	m := map[string]bool{}
	o := []string{}
	for _, v := range in {
		if !m[v] {
			m[v] = true
			o = append(o, v)
		}
	}

	return o
}

func validDNS(s string, wild bool) error {
	if wild {
		if !strings.HasPrefix(s, "*.") || strings.Count(s, "*") != 1 || strings.Count(strings.TrimPrefix(s, "*."), ".") < 1 {
			return fmt.Errorf("wildcard must be like *.example.com: %s", s)
		}

		s = strings.TrimPrefix(s, "*.")
	} else if strings.Contains(s, "*") {
		return fmt.Errorf("use --wildcard-dns for %s", s)
	}
	if len(s) > 253 || !strings.Contains(s, ".") {
		return fmt.Errorf("invalid DNS: %s", s)
	}

	for part := range strings.SplitSeq(s, ".") {
		if len(part) == 0 || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return fmt.Errorf("invalid DNS: %s", s)
		}

		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("invalid DNS: %s", s)
			}
		}
	}

	return nil
}

func validSPIFFE(s string) error {
	_, e := identitycore.SPIFFE(s)
	return e
}

func validateDistributionURLs(label string, values []string) error {
	for _, value := range values {
		if len(value) > 2048 {
			return fmt.Errorf("%s exceeds 2048 bytes", label)
		}

		u, err := url.ParseRequestURI(value)
		if err != nil || len(u.Scheme) == 0 || len(u.Host) == 0 || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("invalid %s %q: expected absolute HTTP(S) URL", label, value)
		}
	}

	return nil
}

func readRecords(path string) ([]record, error) {
	f, e := os.Open(path)
	if e != nil {
		if os.IsNotExist(e) {
			return nil, nil
		}

		return nil, e
	}
	defer f.Close()

	var out []record
	s := bufio.NewScanner(f)
	for s.Scan() {
		var r record
		if e := json.Unmarshal(s.Bytes(), &r); e != nil {
			return nil, e
		}
		if e := validateSchemaVersion(r.SchemaVersion); e != nil {
			return nil, fmt.Errorf("registry record %s: %w", r.Serial, e)
		}
		if r.SchemaVersion == 0 {
			r.SchemaVersion = storageSchemaVersion
		}

		out = append(out, r)
	}

	return out, s.Err()
}

func writeRecords(path string, rs []record) error {
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	for _, r := range rs {
		r.SchemaVersion = storageSchemaVersion
		if e := enc.Encode(r); e != nil {
			return e
		}
	}

	return storagecore.WriteAtomic(path, data.Bytes(), 0600, true)
}

func reasonCode(s string) int {
	switch s {
	case "keyCompromise":
		return 1
	case "caCompromise":
		return 2
	case "affiliationChanged":
		return 3
	case "superseded":
		return 4
	case "cessationOfOperation":
		return 5
	case "certificateHold":
		return 6
	case "removeFromCRL":
		return 8
	case "privilegeWithdrawn":
		return 9
	case "aaCompromise":
		return 10
	default:
		return 0
	}
}

func validReason(s string) bool {
	switch s {
	case "unspecified", "keyCompromise", "caCompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL", "privilegeWithdrawn", "aaCompromise":
		return true
	}

	return false
}
