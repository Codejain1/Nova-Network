#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${DATA_DIR:-$ROOT_DIR/node_data}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/backups}"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env.live}"
KEEP="${KEEP:-14}"
LABEL="${LABEL:-jito}"

usage() {
  cat <<'EOF'
Usage: backup_state.sh [--data-dir DIR] [--out-dir DIR] [--env-file FILE] [--keep N] [--label NAME]
Creates a compressed backup containing public/private chain state and key config files.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --keep) KEEP="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ ! -d "$DATA_DIR" ]]; then
  echo "data dir not found: $DATA_DIR" >&2
  exit 1
fi

for f in public_chain.json private_chain.json; do
  if [[ ! -f "$DATA_DIR/$f" ]]; then
    echo "missing required file: $DATA_DIR/$f" >&2
    exit 1
  fi
done

cp "$DATA_DIR/public_chain.json" "$TMP_DIR/"
cp "$DATA_DIR/private_chain.json" "$TMP_DIR/"
[[ -f "$DATA_DIR/peers.json" ]] && cp "$DATA_DIR/peers.json" "$TMP_DIR/"
[[ -f "$DATA_DIR/faucet_state.json" ]] && cp "$DATA_DIR/faucet_state.json" "$TMP_DIR/"
[[ -f "$ENV_FILE" ]] && cp "$ENV_FILE" "$TMP_DIR/env.live"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="$OUT_DIR/${LABEL}-state-${STAMP}.tar.gz"
tar -C "$TMP_DIR" -czf "$ARCHIVE" .

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$ARCHIVE" > "${ARCHIVE}.sha256"
fi

echo "Backup created: $ARCHIVE"
[[ -f "${ARCHIVE}.sha256" ]] && echo "Checksum: ${ARCHIVE}.sha256"

# Retention
if [[ "$KEEP" =~ ^[0-9]+$ ]] && [[ "$KEEP" -ge 1 ]]; then
  mapfile -t old_files < <(ls -1t "$OUT_DIR/${LABEL}-state-"*.tar.gz 2>/dev/null | tail -n +"$((KEEP+1))")
  for f in "${old_files[@]}"; do
    rm -f "$f" "${f}.sha256"
    echo "Pruned old backup: $f"
  done
fi
