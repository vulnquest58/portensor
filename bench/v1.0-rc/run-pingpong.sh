#!/usr/bin/env bash
set -euo pipefail

TARGET="10.129.219.98"
OUT="/root/portensor-evidence"
BIN="/root/portensor-bin/portensor"
SCOPE="/root/portensor-evidence/lab-scope-pingpong.toml"
PACKS="/root/portensor-packs/official-baseline"
PORTS="53,88,135,139,445,464,593,636,3269,49664,49669,49674,55840,55981,55985"
INITIAL_COOLDOWN="${INITIAL_COOLDOWN:-120}"

mkdir -p "$OUT"

scan_inventory() {
  "$BIN" scan \
    -t "$TARGET" \
    --scope "$SCOPE" \
    -p "$PORTS" \
    --syn \
    --connect-only \
    --profile careful \
    --rate 10 \
    --retries 2 \
    --timeout 5 \
    --show all \
    --format json \
    --no-live \
    -o "$OUT/portensor-inventory-syn.json" \
    2> "$OUT/portensor-inventory-syn.stderr.log"
}

{
  date -u +"started_utc=%Y-%m-%dT%H:%M:%SZ"
  uname -a
  "$BIN" --version
  sha256sum "$BIN"
  ip -brief addr
  ip route
  openvpn --version | head -n 1
  nmap --version | head -n 1
  printf '\nscope:\n'
  cat "$SCOPE"
} > "$OUT/environment.txt" 2>&1

sleep "$INITIAL_COOLDOWN"

scan_inventory

if [ "$(jq -r '.summary.open' "$OUT/portensor-inventory-syn.json")" -eq 0 ]; then
  echo "inventory returned 0 open; retrying after 120s cooldown" >&2
  sleep 120
  scan_inventory
fi

jq -r '.open[].port' "$OUT/portensor-inventory-syn.json" > "$OUT/open-ports.txt"

sleep 30

"$BIN" scan \
  -t "$TARGET" \
  --scope "$SCOPE" \
  -p "$PORTS" \
  --syn \
  --show all \
  --scripts "$PACKS" \
  --advisories \
  --no-db-update \
  --profile careful \
  --rate 10 \
  --retries 2 \
  --timeout 5 \
  --format json \
  --no-live \
  -o "$OUT/portensor-open.json" \
  2> "$OUT/portensor-open.stderr.log"

sleep 30

"$BIN" scan \
  -t "$TARGET" \
  --scope "$SCOPE" \
  -p "$PORTS" \
  --syn \
  --show all \
  --scripts "$PACKS" \
  --advisories \
  --no-db-update \
  --profile careful \
  --rate 10 \
  --retries 2 \
  --timeout 5 \
  --format html \
  --no-live \
  -o "$OUT/portensor-open.html" \
  2> "$OUT/portensor-open-html.stderr.log"

sleep 30

nmap -Pn -n -p- --min-rate 1000 --max-retries 2 -T4 \
  -oN "$OUT/nmap-full.txt" \
  -oX "$OUT/nmap-full.xml" \
  "$TARGET"

sleep 30

nmap -Pn -n -p "$PORTS" -sV -sC \
  -oN "$OUT/nmap-services.txt" \
  -oX "$OUT/nmap-services.xml" \
  "$TARGET"

date -u +"finished_utc=%Y-%m-%dT%H:%M:%SZ" >> "$OUT/environment.txt"
