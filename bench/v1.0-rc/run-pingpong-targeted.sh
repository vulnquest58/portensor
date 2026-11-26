#!/usr/bin/env bash
set -euo pipefail

TARGET="10.129.219.98"
OUT="/root/portensor-evidence"
BIN="/root/portensor-bin/portensor"
SCOPE="/root/portensor-evidence/lab-scope-pingpong.toml"
PACKS="/root/portensor-packs/official-baseline"
PORTS="53,88,135,139,445,464,593,636,3269,49664,49669,49674,55840,55981,55985"

date -u +"targeted_started_utc=%Y-%m-%dT%H:%M:%SZ"

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

jq .summary "$OUT/portensor-inventory-syn.json"
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

jq .summary "$OUT/portensor-open.json"
jq -r '.open[].port' "$OUT/portensor-open.json"

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

date -u +"targeted_finished_utc=%Y-%m-%dT%H:%M:%SZ"
