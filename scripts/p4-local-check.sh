#!/usr/bin/env bash
# Reproduce local P4 tooling evidence. This does not prove external ownership,
# production key custody, clean-runner execution, or OT assessment approval.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n1)"
EVIDENCE="${PORTENSOR_P4_EVIDENCE:-$ROOT/bench/p4}"
SBOM="$ROOT/dist/portensor-$VERSION.cdx.json"
EVIDENCE_SBOM="$EVIDENCE/portensor-$VERSION.cdx.json"
LINUX_ARCHIVE="$ROOT/dist/portensor-$VERSION-linux-x86_64.tar.gz"
WINDOWS_ARCHIVE="$ROOT/dist/portensor-$VERSION-windows-x86_64.zip"
SUMS="$ROOT/dist/SHA256SUMS"
TMP="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    printf 'p4-local-check: %s\n' "$*" >&2
    exit 1
}

[ -n "$VERSION" ] || fail "could not read Cargo.toml version"
[ -f "$LINUX_ARCHIVE" ] || fail "missing $LINUX_ARCHIVE; run 'make dist' first"
[ -f "$WINDOWS_ARCHIVE" ] || fail "missing $WINDOWS_ARCHIVE; run 'make dist' first"
command -v gpg >/dev/null || fail "gpg is required"
command -v cargo >/dev/null || fail "cargo is required"
command -v python3 >/dev/null || fail "python3 is required"
[ -x "$(command -v cargo-cyclonedx 2>/dev/null || true)" ] || fail "cargo-cyclonedx is required"
mkdir -p "$EVIDENCE" "$ROOT/dist"

cargo cyclonedx --format json --spec-version 1.5 \
    --override-filename "portensor-$VERSION.cdx" >/dev/null
mv -f "portensor-$VERSION.cdx.json" "$SBOM"
cp -f "$SBOM" "$EVIDENCE_SBOM"

python3 - "$SBOM" "$EVIDENCE_SBOM" <<'PY'
import json
import sys
from pathlib import Path

sbom_path = Path(sys.argv[1])
evidence_path = Path(sys.argv[2])
sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
if sbom.get("bomFormat") != "CycloneDX":
    raise SystemExit("SBOM is not CycloneDX")
if sbom.get("specVersion") not in {"1.5", "1.6", "1.7"}:
    raise SystemExit(f"unexpected CycloneDX spec version: {sbom.get('specVersion')}")
components = sbom.get("components") or []
if len(components) < 100:
    raise SystemExit(f"SBOM has too few components: {len(components)}")
if not evidence_path.is_file() or evidence_path.read_bytes() != sbom_path.read_bytes():
    raise SystemExit("evidence SBOM does not match the generated SBOM")
print(f"sbom_format={sbom['bomFormat']} spec={sbom['specVersion']} components={len(components)}")
PY

(
    cd "$ROOT/dist"
    sha256sum "$(basename "$LINUX_ARCHIVE")" "$(basename "$WINDOWS_ARCHIVE")" "$(basename "$SBOM")" > SHA256SUMS.tmp
    mv -f SHA256SUMS.tmp SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)

python3 - "$SBOM" "$EVIDENCE_SBOM" "$SUMS" <<'PY'
import hashlib
import sys
from pathlib import Path

sbom_path = Path(sys.argv[1])
evidence_path = Path(sys.argv[2])
sums_path = Path(sys.argv[3])
expected_name = sbom_path.name
listed = {}
for line in sums_path.read_text(encoding="utf-8").splitlines():
    parts = line.split()
    if len(parts) == 2:
        listed[parts[1]] = parts[0]
if expected_name not in listed:
    raise SystemExit(f"SBOM is not listed in SHA256SUMS: {expected_name}")
actual = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
if listed[expected_name] != actual:
    raise SystemExit("SBOM checksum does not match SHA256SUMS")
if not evidence_path.is_file() or evidence_path.read_bytes() != sbom_path.read_bytes():
    raise SystemExit("evidence SBOM does not match the checksummed SBOM")
PY

cp "$SUMS" "$TMP/SHA256SUMS"

export GNUPGHOME="$TMP/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "portensor P4 test <p4@portensor.invalid>" ed25519 sign 1d \
    >/dev/null 2>&1
gpg_fingerprint="$(
    gpg --list-secret-keys --with-colons |
        awk -F: '/^fpr:/ { print $10; exit }'
)"
[ -n "$gpg_fingerprint" ] || fail "failed to create the GPG test key"
gpg --batch --yes --armor --detach-sign --local-user "$gpg_fingerprint" \
    --output "$TMP/SHA256SUMS.asc" "$TMP/SHA256SUMS"
gpg --armor --export "$gpg_fingerprint" > "$TMP/gpg-test-public.asc"
export GNUPGHOME="$TMP/gnupg-verify"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --import "$TMP/gpg-test-public.asc" >/dev/null 2>&1
gpg --verify "$TMP/SHA256SUMS.asc" "$TMP/SHA256SUMS" >/dev/null 2>&1 ||
    fail "GPG signature verification failed with the exported public key"

cosign_status="skipped: cosign not installed"
if command -v cosign >/dev/null; then
    COSIGN_PASSWORD="" cosign generate-key-pair \
        --output-key-prefix "$TMP/cosign-test" >/dev/null
    COSIGN_PASSWORD="" cosign sign-blob --yes \
        --key "$TMP/cosign-test.key" \
        --bundle "$TMP/SHA256SUMS.cosign.bundle" \
        "$TMP/SHA256SUMS" >/dev/null
    cosign verify-blob --key "$TMP/cosign-test.pub" \
        --bundle "$TMP/SHA256SUMS.cosign.bundle" \
        "$TMP/SHA256SUMS" >/dev/null
    cosign public-key --key "$TMP/cosign-test.key" \
        --outfile "$TMP/cosign-test-derived.pub" >/dev/null
    cmp -s "$TMP/cosign-test.pub" "$TMP/cosign-test-derived.pub" ||
        fail "cosign public key derivation failed"
    cosign_status="verified: $(cosign version 2>/dev/null | awk -F': *' '/GitVersion/ { print $2; exit }')"
fi

workflow=".github/workflows/release.yml"
for needle in \
    'cargo cyclonedx' \
    'actions/attest-build-provenance@' \
    'actions/attest-sbom@' \
    'cosign verify-blob' \
    'gpg --verify'; do
    grep -Fq "$needle" "$workflow" || fail "release workflow is missing: $needle"
done

cat > "$EVIDENCE/p4-local-check.txt" <<EOF
version=$VERSION
gpg_fingerprint=$gpg_fingerprint
gpg_signature=verified
cosign_signature=$cosign_status
sbom=CycloneDX 1.5, $EVIDENCE_SBOM
checksum_manifest=archives+sbom
workflow_signing_and_attestations=present
scope=p4 local tooling validation only
external_key_custody=not verified
registry_ownership=not verified
clean_runner_execution=not verified
ot_assessment_approval=not verified
EOF

printf 'p4-local-check: local signing, SBOM, and checksum checks passed\n'
printf 'p4-local-check: evidence written to %s\n' "$EVIDENCE"
printf 'p4-local-check: external P4 approvals are not covered by this check\n'
