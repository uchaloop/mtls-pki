# Changelog

All notable changes to this project are documented in this file.

## v0.1.0

### What's Changed

* Add an offline Root CA with staged, compatible rotation and a trust bundle of active generations
* Add dedicated server and client issuing CAs with generation-aware rotation
* Add RSA and ECDSA key generation with password-protected CA keys
* Add server and client certificates with DNS, wildcard DNS, IP, URI and SPIFFE SANs
* Add optional Subject fields, AIA, CRL distribution point and OCSP URLs
* Add CSR creation, inspection and signing
* Add a certificate registry, revocation records and CRL generation
* Add certificate inspection, chain/purpose/hostname verification and renewal-window checks
* Add PEM, JSON, Kubernetes Secret and PKCS#12 exports without external OpenSSL
* Add a PKI `doctor` with key, chain, registry, history, orphan and CRL validation
* Add a transaction journal with automatic and explicit recovery
* Add a versioned storage schema with legacy compatibility checks
* Add file locking so concurrent commands cannot corrupt the PKI
* Add JSON profiles, environment overrides and CLI overrides
* Add text and JSON output plus a dry-run mode for every mutating command
* Add password sources for keys: environment variable, file, stdin and terminal prompt
* Build the CLI on Cobra and require Go 1.26.6 for the ASN.1 recursion-depth security fix
* Add unit, integration and CLI contract tests, fuzz targets for untrusted serialized input, and reproducible-friendly builds with embedded version metadata
* Add repository instructions for security-sensitive Codex changes
* Add cross-platform CI, race and integration tests, vulnerability scanning and tracked-secret checks
* Add deterministic multi-platform release archives and SHA-256 checksums
* Normalize text files across platforms and expand local PKI artifact exclusions
* Reject path-segment and oversized PKI, issuer and certificate names consistently across commands
* Verify CRLs only against the issuer from a successfully verified certificate chain
* Use the `go-pkcs12` release containing the GO-2026-5052 fix
* Require password protection for new Root and issuer keys unless unencrypted storage is explicitly allowed
* Validate Kubernetes Secret and namespace names before rendering manifests
* Report private keys and PKCS#12 files exposed through group or other filesystem permissions in `doctor`
* Preserve atomic file writes on Windows without attempting unsupported directory descriptor synchronization
