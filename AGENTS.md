# Repository instructions

These instructions apply to the whole repository.

## Product and security boundaries

- This repository implements a filesystem-backed private mTLS PKI. Treat changes to key generation, certificate profiles, signing, verification, revocation, rotation, storage and export as security-sensitive.
- Never add generated private keys, certificates, CSRs, PKCS#12 files, passwords, real PKI storage or other secrets to Git.
- Passwords must only come from the supported environment, file, stdin or terminal sources. Do not add literal password flags, configuration fields or logs.
- Keep Root, server issuer, client issuer and partner issuer responsibilities separated.
- TLS identities are verified through SANs. Do not make Subject CN an identity or hostname fallback.
- Do not weaken key sizes, signature algorithms, certificate constraints, path-length constraints, key usages or extended key usages without an explicit requirement and focused tests.

## Storage and mutation safety

- Preserve filesystem locking, staged writes, atomic replacement, transaction journaling and recovery behavior.
- Private keys must retain restrictive filesystem permissions.
- A failed mutating operation must not leave a partially committed certificate, registry record, trust bundle, CRL or rotation state.
- Storage format changes require compatibility tests. Unknown future schema versions must remain rejected.
- Preserve immutable generation-addressed history and registry references during renewal and rotation.

## Development workflow

- Add or update the smallest focused test for every behavior change.
- Use temporary directories in tests. Do not write test PKI state into the repository.
- Keep CLI behavior, exit codes, JSON output and dry-run behavior synchronized with tests and documentation.
- Update `README.md` for public behavior and operational workflow changes.
- Update `CHANGELOG.md` for release-visible changes.
- Do not mix unrelated cleanup with a security-sensitive change.
- Remove dead code before completing the task.

## Required checks

Run before completing a coherent change:

- `gofmt` and verify that no Go file remains unformatted;
- `go vet ./...`;
- `go test -race ./...`;
- `make integration` when CLI, storage, signing, verification, export, rotation or recovery behavior changes;
- `make cross` when build or dependency behavior changes;
- `git diff --check` when the directory is a Git worktree.

## Dependencies and releases

- Prefer the Go standard library and a small dependency surface.
- Review the maintenance status, license, security history and architectural fit before adding a dependency.
- Keep `go.mod` and `go.sum` tidy.
- Release builds must use `CGO_ENABLED=0`, `-trimpath` and embedded version metadata.
- A release tag must match the released version. Published archives must include checksums and pass a binary smoke test.
