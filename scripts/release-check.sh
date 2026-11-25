#!/usr/bin/env bash
# Pre-tag release gate: version consistency, clean tree, and artifact checks.
# Full build/test/audit gates are run by `make release-check`.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
    printf 'release-check: %s\n' "$*" >&2
    exit 1
}

allow_dirty="${PORTENSOR_RELEASE_CHECK_ALLOW_DIRTY:-0}"
if [ "$allow_dirty" != "1" ]; then
    if [ -n "$(git status --porcelain)" ]; then
        git status --short >&2
        fail "working tree is not clean; commit or stash changes first"
    fi
fi

[ -f .github/actionlint.yaml ] || fail "missing .github/actionlint.yaml"
[ -f CHANGELOG.md ] || fail "missing CHANGELOG.md"
[ -f man/portensor.1 ] || fail "missing man/portensor.1"

cargo_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n1)
lock_version=$(awk '
    /^name = "portensor"$/ { getline; sub(/^version = "/, ""); sub(/"$/, ""); print; exit }
' Cargo.lock)
make_version=$(sed -n 's/^VERSION[[:space:]]*?=[[:space:]]*\([^[:space:]]*\).*/\1/p' Makefile | head -n1)
readme_version=$(sed -n 's/.*badge\/version-v\([0-9][0-9.]*\)-blue.*/\1/p' README.md | head -n1)
changelog_version=$(awk '
    /^## \[[0-9]+\.[0-9]+\.[0-9]+\]/ {
        line = $0
        sub(/^## \[/, "", line)
        sub(/\].*/, "", line)
        print line
        exit
    }
' CHANGELOG.md)
man_version=$(grep -m1 -oE 'portensor [0-9]+\.[0-9]+\.[0-9]+' man/portensor.1 | awk '{ print $2 }')

[ -n "$cargo_version" ] || fail "could not read Cargo.toml version"
[ -n "$lock_version" ] || fail "could not read Cargo.lock portensor version"
[ -n "$make_version" ] || fail "could not read Makefile VERSION"
[ -n "$readme_version" ] || fail "could not read README version badge"
[ -n "$changelog_version" ] || fail "could not read latest CHANGELOG release"
[ -n "$man_version" ] || fail "could not read man page version"

printf 'release-check: Cargo.toml=%s Cargo.lock=%s Makefile=%s README=%s CHANGELOG=%s man=%s\n' \
    "$cargo_version" "$lock_version" "$make_version" "$readme_version" \
    "$changelog_version" "$man_version"

for pair in \
    "Cargo.toml:$cargo_version" \
    "Cargo.lock:$lock_version" \
    "Makefile:$make_version" \
    "README.md:$readme_version" \
    "CHANGELOG.md:$changelog_version" \
    "man/portensor.1:$man_version"; do
    name="${pair%%:*}"
    value="${pair#*:}"
    [ "$value" = "$cargo_version" ] || fail "$name version $value does not match $cargo_version"
done

sbom="dist/portensor-$cargo_version.cdx.json"
if compgen -G "dist/portensor-$cargo_version-*" >/dev/null; then
    [ -f dist/SHA256SUMS ] || fail "release artifacts exist but dist/SHA256SUMS is missing"
    [ -f "$sbom" ] || fail "release artifacts exist but $sbom is missing"
    grep -Fq "  portensor-$cargo_version.cdx.json" dist/SHA256SUMS ||
        fail "SHA256SUMS does not include $sbom"
    (cd dist && sha256sum -c SHA256SUMS)
    python3 - "$sbom" <<'PY'
import json
import sys
from pathlib import Path

sbom = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if sbom.get("bomFormat") != "CycloneDX":
    raise SystemExit("release-check: SBOM is not CycloneDX")
if sbom.get("specVersion") not in {"1.5", "1.6", "1.7"}:
    raise SystemExit(f"release-check: unsupported SBOM spec version: {sbom.get('specVersion')}")
components = sbom.get("components") or []
if len(components) < 100:
    raise SystemExit(f"release-check: SBOM has too few components: {len(components)}")
PY
else
    printf 'release-check: no %s dist archives present; skipping artifact verification\n' \
        "$cargo_version"
fi

printf 'release-check: version, tree, and artifact checks passed for %s\n' "$cargo_version"
