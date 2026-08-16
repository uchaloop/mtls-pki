# mtls-pki

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`mtls-pki` is a standalone CLI for operating a small filesystem-backed private mTLS PKI. It has no Kubernetes, organization, domain or environment conventions.

## PKI model

```text
offline Root CA
├── server issuing CA ── server certificates
├── client issuing CA ── internal client certificates
└── partner issuing CA ── isolated external clients
```

The Root signs issuing CAs. An issuer is restricted to either server or client certificates. Applications must trust only the required Root/issuer chain and enforce revocation independently.

Default validity:

| Object | Days |
|---|---:|
| Root CA | 3650 |
| Issuing CA | 1825 |
| Server certificate | 180 |
| Client certificate | 365 |

A child cannot outlive its parent. Certificates start five minutes in the past to tolerate minor clock skew.

## Install

### go install

```bash
go install github.com/uchaloop/mtls-pki/cmd/mtls-pki@latest
```

The binary lands in `$(go env GOPATH)/bin`. Append `@v0.1.0` to pin a release. Go 1.26.6 or newer within the Go 1.26 line is required: this minimum includes the ASN.1 recursion-depth security fix used by PKCS#8 parsing.

### Release archives

Every tag publishes archives for Linux, macOS, Windows and FreeBSD on the [releases page](https://github.com/uchaloop/mtls-pki/releases), alongside `checksums.txt`:

```bash
tar -xzf mtls-pki_0.1.0_linux_amd64.tar.gz
mtls-pki_0.1.0_linux_amd64/mtls-pki --version
```

Windows archives are `.zip` and contain `mtls-pki.exe`.

### From source

```bash
make build     # ./bin/mtls-pki
make install   # $(go env GOPATH)/bin/mtls-pki
make dist      # every published platform into ./dist
```

The implementation generates encrypted PKCS#8 and PKCS#12 in-process. OpenSSL is not required.

## Create a PKI

```bash
# This intentionally creates unencrypted CA keys for a local demonstration.
bin/mtls-pki root create -p company \
  --allow-unencrypted-key

bin/mtls-pki issuer create \
  -p company -n servers --type server \
  --allow-unencrypted-key

bin/mtls-pki issuer create \
  -p company -n clients --type client \
  --allow-unencrypted-key
```

The default storage root is `pki`. Override it with `--root` or `-r`.
Root and issuer private keys require password protection by default. The explicit
`--allow-unencrypted-key` opt-out is intended only for disposable local and test PKIs.

## Issue certificates

Server:

```bash
bin/mtls-pki server issue \
  -p company -i servers -n example-api \
  -d api.example.com,api.internal.example.com \
  --wildcard-dns '*.apps.example.com' \
  --ip 10.20.30.40 \
  --spiffe-id spiffe://example.org/service/example-api
```

Client:

```bash
bin/mtls-pki client issue \
  -p company -i clients -n orders-api \
  --uri urn:example:client:orders-api \
  --subject-o 'Example Corp' \
  --subject-ou Platform
```

DNS, wildcard DNS, IP, URI and SPIFFE flags are repeatable and accept CSV. A server wildcard must have the form `*.example.com` and matches one label level. Client wildcards are rejected. TLS hostname verification uses SAN, not Subject CN.

Supported key algorithms:

```bash
--key-algorithm rsa --rsa-bits 3072
--key-algorithm ecdsa --curve P-256
```

RSA sizes: 2048, 3072 and 4096. ECDSA curves: P-256 and P-384.

## Renew certificates

Renew inherits the current Subject and SANs unless replacements are supplied:

```bash
bin/mtls-pki server renew \
  -p company -i servers -n example-api
```

Conditional renewal:

```bash
bin/mtls-pki server renew \
  -p company -i servers -n example-api \
  --renew-before 720h
```

The previous leaf directory is archived by its certificate serial. Registry records retain the exact immutable historical certificate path.

## CSR workflow

Generate a key and CSR outside the PKI:

```bash
bin/mtls-pki csr create \
  -n partner-client \
  --spiffe-id spiffe://partner.example/client/orders \
  --out ./request
```

Inspect and sign it:

```bash
bin/mtls-pki csr inspect ./request/partner-client.csr

bin/mtls-pki csr sign \
  -p company -i clients --type client \
  -n partner-client \
  --csr ./request/partner-client.csr
```

The private key remains with the CSR creator.

## Password-protected keys

Root and issuer private keys must be encrypted unless `--allow-unencrypted-key`
is explicitly supplied. Passwords can come from an environment variable, a file
or stdin. Literal password flags are intentionally unavailable.

```bash
bin/mtls-pki root create -p company \
  --key-pass-env ROOT_PASSWORD

bin/mtls-pki issuer create \
  -p company -n servers --type server \
  --parent-pass-env ROOT_PASSWORD \
  --key-pass-file /secure/server-issuer.password

bin/mtls-pki server issue \
  -p company -i servers -n api -d api.example.com \
  --issuer-pass-file /secure/server-issuer.password
```

PKCS#12 is optional:

```bash
bin/mtls-pki client issue ... \
  --p12 --p12-pass-env P12_PASSWORD
```

## Configuration

Priority:

```text
CLI flags → MTLS_PKI_* environment → JSON profile → defaults
```

```bash
bin/mtls-pki server issue \
  --config config.example.json ...
```

Supported environment variables:

- `MTLS_PKI_ROOT_DAYS`
- `MTLS_PKI_ISSUER_DAYS`
- `MTLS_PKI_SERVER_DAYS`
- `MTLS_PKI_CLIENT_DAYS`
- `MTLS_PKI_KEY_ALGORITHM`
- `MTLS_PKI_RSA_BITS`
- `MTLS_PKI_ECDSA_CURVE`

Passwords do not belong in the JSON profile.

## Root and issuer rotation

Root rotation is a staged trust-bundle transition:

```bash
bin/mtls-pki root rotate -p company \
  --key-pass-env NEW_ROOT_PASSWORD
bin/mtls-pki root rotation status -p company

# Rotate/reissue all issuers and leaves onto the new Root.

bin/mtls-pki root rotation finalize -p company
```

Finalization is blocked while an active issuer or valid leaf still depends on the previous Root.

Issuer rotation preserves generation-addressed certificates and CRLs:

```bash
bin/mtls-pki issuer rotate \
  -p company -n servers --type server \
  --parent-pass-env ROOT_PASSWORD \
  --key-pass-env NEW_SERVER_ISSUER_PASSWORD
```

Rotation is blocked while valid leaves use the active issuer unless `--allow-active-certificates` is explicitly supplied.

## Inspect, verify and list

```bash
bin/mtls-pki inspect pki/company/certificates/server/example-api/certs/server.crt

bin/mtls-pki verify \
  pki/company/certificates/server/example-api/certs/server.crt \
  --ca pki/company/root/certs/trust-bundle.crt \
  --untrusted pki/company/issuers/servers/certs/issuer.crt \
  --purpose server \
  --hostname api.example.com

bin/mtls-pki list -p company --status valid
bin/mtls-pki issuer list -p company
bin/mtls-pki issuer inspect -p company -n servers
```

Use `--output json` or `-o json` for machine-readable output.

## Revocation and CRL

```bash
bin/mtls-pki revoke -p company \
  --certificate pki/company/certificates/client/orders-api/certs/client.crt \
  --reason keyCompromise

bin/mtls-pki crl generate \
  -p company -i clients --generation 1 --days 7
```

CRLs are stored per issuer generation. The active generation is also projected to `issuers/<issuer>/crl/issuer.crl`. Revocation becomes effective only when the verifier loads and enforces the relevant CRL.

## Export

```bash
bin/mtls-pki export \
  -p company --type client -n orders-api \
  --format pem --out orders-api.pem

bin/mtls-pki export \
  -p company --type server -n example-api \
  --format kubernetes \
  --secret-name example-api-tls \
  --namespace example \
  --out example-api-secret.yaml
```

Kubernetes Secret names must be DNS-1123 subdomains. Namespaces must be
DNS-1123 labels. Invalid names are rejected before certificate material is read.

Formats: `pem`, `json`, `kubernetes`. Private-key export requires the explicit `--include-private-key` flag where applicable.

## Audit and recovery

Audit the complete PKI without modifying it:

```bash
bin/mtls-pki doctor -p company
bin/mtls-pki doctor -p company -o json
```

For encrypted CA keys:

```bash
bin/mtls-pki doctor -p company \
  --root-pass-env ROOT_PASSWORD \
  --issuer-pass-file /secure/issuer.password
```

`doctor` checks Root and issuer chains, key matching, generations, registry, historical leaves, orphan files, CRL signatures/numbers and pending transactions.

Mutating operations automatically recover an interrupted leaf transaction. Recovery can also be requested explicitly:

```bash
bin/mtls-pki recover -p company
```

## Storage

```text
pki/<pki>/
├── root/
│   ├── certs/{root.crt,trust-bundle.crt}
│   ├── private/root.key
│   ├── history/
│   └── metadata.json
├── issuers/<issuer>/
│   ├── generations/<generation>/{certs,private,crl}
│   ├── certs/issuer.crt
│   ├── private/issuer.key
│   ├── crl/{issuer.crl,number}
│   └── metadata.json
├── certificates/{server|client}/
│   ├── <name>/{certs,private}
│   └── history/<name>-<serial>/{certs,private}
└── index/{certificates.jsonl,transaction.json}
```

Metadata and registry records contain `schemaVersion`. Schema-less v0.1 development data remains readable as schema version 1; unknown future versions are rejected.

`chain.crt` contains issuer + Root. `fullchain.crt` contains leaf + issuer. The Root trust anchor is distributed separately.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success |
| 1 | Operational/storage error |
| 2 | Invalid command or input |
| 3 | Verification or doctor failure |
| 4 | Certificate is inside its renewal window |
| 5 | Certificate is revoked |

## Development and release

```bash
make test
make vet
make modernize-check
make integration
make cross
```

GitHub Actions runs formatting, module consistency, modernization, vet, race,
integration, cross-platform and vulnerability checks. It also rejects tracked
PKI material and PEM private keys.

Release build:

```bash
make release \
  VERSION=1.0.0 \
  COMMIT=abc123 \
  BUILD_DATE=2026-08-16 \
  GOOS=linux GOARCH=amd64
```

A pushed `v*` tag builds reproducible archives for the supported platforms,
creates `checksums.txt` and publishes the files to GitHub Releases. The tag is
embedded into the binary as its version.

## Scope

- Filesystem storage only; no Vault/HSM/KMS backend.
- No OCSP responder or automatic-renewal daemon.
- CRLs must be distributed and enforced by the operator.
- Locking assumes a local POSIX-style filesystem and one shared storage host.

## License

Distributed under the [MIT License](LICENSE).
