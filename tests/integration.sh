#!/usr/bin/env bash
set -euo pipefail

work="$(mktemp -d "${TMPDIR:-/tmp}/mtls-pki-integration.XXXXXX")"
trap 'rm -rf "$work"' EXIT
cli="$(cd "$(dirname "$0")/.." && pwd)/bin/mtls-pki"

assert_exit() {
  expected="$1"
  shift
  set +e
  "$@" >/dev/null 2>&1
  actual="$?"
  set -e
  test "$actual" -eq "$expected" || { echo "expected exit $expected, got $actual: $*" >&2; exit 1; }
}

assert_exit 2 "$cli" root create --root "$work/password-required" --pki test
assert_exit 2 env EMPTY_CA_PASSWORD= "$cli" root create \
  --root "$work/empty-password" --pki test --key-pass-env EMPTY_CA_PASSWORD
env ROOT_PASSWORD=root-secret "$cli" root create \
  --root "$work/protected" --pki test --key-pass-env ROOT_PASSWORD
env ROOT_PASSWORD=root-secret ISSUER_PASSWORD=issuer-secret "$cli" issuer create \
  --root "$work/protected" --pki test --name servers --type server \
  --parent-pass-env ROOT_PASSWORD --key-pass-env ISSUER_PASSWORD
grep -q 'BEGIN ENCRYPTED PRIVATE KEY' "$work/protected/test/root/private/root.key"
grep -q 'BEGIN ENCRYPTED PRIVATE KEY' "$work/protected/test/issuers/servers/private/issuer.key"
"$cli" root create --root "$work" --pki test --allow-unencrypted-key
"$cli" issuer create --root "$work" --pki test --name servers --type server --allow-unencrypted-key
"$cli" issuer create --root "$work" --pki test --name clients --type client --allow-unencrypted-key
old_root_fingerprint="$(openssl x509 -in "$work/test/root/certs/root.crt" -noout -fingerprint -sha256)"
"$cli" root rotate --root "$work" --pki test --allow-unencrypted-key
"$cli" root rotation status --root "$work" --pki test --output json | grep -q '"phase": "migrating"'
assert_exit 1 "$cli" root rotate --root "$work" --pki test --allow-unencrypted-key
test "$(grep -c 'BEGIN CERTIFICATE' "$work/test/root/certs/trust-bundle.crt")" -eq 2
openssl crl2pkcs7 -nocrl -certfile "$work/test/root/certs/trust-bundle.crt" | \
  openssl pkcs7 -print_certs -noout | grep -q "test Root CA"
test "$old_root_fingerprint" != "$(openssl x509 -in "$work/test/root/certs/root.crt" -noout -fingerprint -sha256)"
"$cli" server issue --root "$work" --pki test --issuer servers --name api \
  --dns api.example.com --wildcard-dns '*.apps.example.com' --ip 127.0.0.1 \
  --uri spiffe://example.org/service/api
parallel_pids=""
for n in 1 2 3 4; do
  "$cli" server issue --root "$work" --pki test --issuer servers --name "parallel-$n" \
    --dns "parallel-$n.example.com" --key-algorithm ecdsa >"$work/parallel-$n.out" 2>&1 &
  parallel_pids="$parallel_pids $!"
done
for pid in $parallel_pids; do
  wait "$pid"
done
for n in 1 2 3 4; do
  "$cli" list --root "$work" --pki test --name "parallel-$n" --status valid --output json | grep -q "\"name\": \"parallel-$n\""
done
env P12_PASSWORD=test-password "$cli" client issue --root "$work" --pki test --issuer clients --name worker \
  --uri urn:example:client:worker --subject-ou Platform --p12-pass-env P12_PASSWORD --output json | grep -q '"pkcs12"'
"$cli" server renew --root "$work" --pki test --issuer servers --name api
assert_exit 4 "$cli" server renew --root "$work" --pki test --issuer servers --name api --renew-before 1h
assert_exit 1 "$cli" issuer rotate --root "$work" --pki test --name servers --type server --allow-unencrypted-key
"$cli" verify "$work/test/certificates/server/api/certs/server.crt" \
  --ca "$work/test/root/certs/trust-bundle.crt" --untrusted "$work/test/issuers/servers/certs/issuer.crt" \
  --purpose server --hostname api.example.com
test -s "$work/test/issuers/servers/generations/000001/certs/issuer.crt"
"$cli" issuer rotate --root "$work" --pki test --name servers --type server --allow-active-certificates --allow-unencrypted-key
test -s "$work/test/issuers/servers/generations/000002/certs/issuer.crt"
"$cli" server issue --root "$work" --pki test --issuer servers --name api-v2 --dns api-v2.example.com \
  --issuer-url https://pki.example.com/issuers/servers.crt \
  --crl-url https://pki.example.com/crl/servers.crl \
  --ocsp-url https://ocsp.example.com
"$cli" inspect "$work/test/certificates/server/api-v2/certs/server.crt" --output json | grep -q 'https://pki.example.com/crl/servers.crl'
"$cli" issuer rotate --root "$work" --pki test --name servers --type server --allow-active-certificates --allow-unencrypted-key
test -s "$work/test/issuers/servers/generations/000003/certs/issuer.crt"
test ! -d "$work/test/issuers/servers/history"
cmp "$work/test/issuers/servers/certs/issuer.crt" "$work/test/issuers/servers/generations/000003/certs/issuer.crt"
"$cli" csr create --name external-worker --cn external-worker --uri spiffe://example.org/client/external-worker --out "$work/csr"
"$cli" csr inspect "$work/csr/external-worker.csr" | grep -q '"signatureValid": true'
"$cli" csr sign --root "$work" --pki test --issuer clients --type client --name external-worker --csr "$work/csr/external-worker.csr"
"$cli" export --root "$work" --pki test --type client --name external-worker --format pem --out "$work/external-worker.pem"
test -s "$work/external-worker.pem"
assert_exit 1 "$cli" export --root "$work" --pki test --type client --name external-worker --format kubernetes --out "$work/external-worker-secret.yaml"
"$cli" csr create --name wildcard-client --dns '*.example.com' --out "$work/csr"
assert_exit 2 "$cli" csr sign --root "$work" --pki test --issuer clients --type client --name wildcard-client --csr "$work/csr/wildcard-client.csr"
test ! -e "$work/test/certificates/client/external-worker/private/client.key"
"$cli" verify "$work/test/certificates/client/external-worker/certs/client.crt" \
  --ca "$work/test/root/certs/trust-bundle.crt" --untrusted "$work/test/issuers/clients/generations/000001/certs/issuer.crt" --purpose client
"$cli" verify "$work/test/certificates/server/api/certs/server.crt" \
  --ca "$work/test/root/certs/trust-bundle.crt" --untrusted "$work/test/issuers/servers/generations/000001/certs/issuer.crt" \
  --purpose server --hostname api.example.com
"$cli" verify "$work/test/certificates/server/api-v2/certs/server.crt" \
  --ca "$work/test/root/certs/trust-bundle.crt" --untrusted "$work/test/issuers/servers/generations/000002/certs/issuer.crt" \
  --purpose server --hostname api-v2.example.com
"$cli" revoke --root "$work" --pki test --certificate "$work/test/certificates/client/worker/certs/client.crt" --reason keyCompromise
"$cli" issuer rotate --root "$work" --pki test --name clients --type client --allow-active-certificates --allow-unencrypted-key
"$cli" crl generate --root "$work" --pki test --issuer clients --generation 1
"$cli" crl generate --root "$work" --pki test --issuer clients --generation 2
"$cli" export --root "$work" --pki test --type server --name api --format kubernetes --out "$work/secret.yaml"
assert_exit 2 "$cli" export --root "$work" --pki test --type server --name api --format kubernetes \
  --secret-name $'api\n  labels: injected' --out "$work/injected-secret.yaml"
test -s "$work/test/issuers/clients/generations/000001/crl/issuer.crl"
test -s "$work/test/issuers/clients/generations/000002/crl/issuer.crl"
test "$(cat "$work/test/issuers/clients/generations/000001/crl/number")" -eq 1
test "$(cat "$work/test/issuers/clients/generations/000002/crl/number")" -eq 1
test -s "$work/secret.yaml"
test -s "$work/test/certificates/client/worker/private/client.p12"
openssl pkcs12 -in "$work/test/certificates/client/worker/private/client.p12" -passin pass:test-password -noout
"$cli" list --root "$work" --pki test --output json | grep -q '"status": "revoked"'
"$cli" list --root "$work" --pki test --output json | grep -q '"status": "superseded"'
"$cli" list --root "$work" --pki test --type server --issuer servers --status valid --name api-v2 --output json | grep -q '"name": "api-v2"'
if "$cli" list --root "$work" --pki test --type client --output json | grep -q '"type": "server"'; then
  echo "list --type client returned a server certificate" >&2
  exit 1
fi
assert_exit 2 "$cli" server issue -r "$work" -p test -i servers -n invalid-url -d invalid-url.example.com --crl-url file:///tmp/issuer.crl
test -d "$work/test/certificates/server/history"
"$cli" verify --help >/dev/null
"$cli" inspect --help >/dev/null
"$cli" server issue -r "$work" -p test -i servers -n dry -d dry.example.com --dry-run -o json | grep -q '"operation": "issue"'
assert_exit 5 "$cli" verify "$work/test/certificates/client/worker/certs/client.crt" \
  --ca "$work/test/root/certs/trust-bundle.crt" --untrusted "$work/test/issuers/clients/generations/000001/certs/issuer.crt" \
  --purpose client --crl "$work/test/issuers/clients/generations/000001/crl/issuer.crl"
assert_exit 2 "$cli" export --root "$work" --pki test --type client --name worker --include-private-key
assert_exit 2 env MTLS_PKI_SERVER_DAYS=invalid "$cli" server issue -r "$work" -p test -i servers -n invalid-env -d invalid.example.com --dry-run
"$cli" issuer retire -r "$work" -p test -n clients
assert_exit 1 "$cli" client issue -r "$work" -p test -i clients -n blocked --uri urn:example:blocked
"$cli" issuer activate -r "$work" -p test -n clients
"$cli" doctor -r "$work" -p test -o json | grep -q '"status": "healthy"'
chmod 0644 "$work/test/root/private/root.key"
set +e
"$cli" doctor -r "$work" -p test -o json >"$work/doctor-insecure-permissions.json"
doctor_exit="$?"
set -e
test "$doctor_exit" -eq 3
grep -q '"code": "private_material_permissions"' "$work/doctor-insecure-permissions.json"
chmod 0600 "$work/test/root/private/root.key"
mv "$work/test/certificates/server/api-v2/certs/server.crt" "$work/api-v2.crt"
assert_exit 3 "$cli" doctor -r "$work" -p test
mv "$work/api-v2.crt" "$work/test/certificates/server/api-v2/certs/server.crt"
assert_exit 1 "$cli" root rotation finalize -r "$work" -p test
