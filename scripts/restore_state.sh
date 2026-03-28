#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${TARGET_DIR:-node_data}"
BACKUP_FILE="${BACKUP_FILE:-}"
FORCE="${FORCE:-false}"

usage() {
  cat <<'EOF'
Usage: restore_state.sh --backup FILE [--target-dir DIR] [--force]
Restores chain state backup created by backup_state.sh.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backup) BACKUP_FILE="$2"; shift 2 ;;
    --target-dir) TARGET_DIR="$2"; shift 2 ;;
    --force) FORCE=true; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$BACKUP_FILE" ]]; then
  echo "--backup is required" >&2
  usage
  exit 1
fi
if [[ ! -f "$BACKUP_FILE" ]]; then
  echo "backup not found: $BACKUP_FILE" >&2
  exit 1
fi

if [[ "$FORCE" != "true" && -d "$TARGET_DIR" ]]; then
  echo "target exists ($TARGET_DIR). Use --force to continue." >&2
  exit 1
fi

if [[ -f "${BACKUP_FILE}.sha256" ]]; then
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "${BACKUP_FILE}.sha256"
  elif command -v shasum >/dev/null 2>&1; then
    expected="$(awk '{print $1}' "${BACKUP_FILE}.sha256")"
    actual="$(shasum -a 256 "$BACKUP_FILE" | awk '{print $1}')"
    [[ "$expected" == "$actual" ]] || { echo "checksum mismatch" >&2; exit 1; }
  fi
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
tar -C "$TMP_DIR" -xzf "$BACKUP_FILE"

mkdir -p "$TARGET_DIR"
for f in public_chain.json private_chain.json peers.json faucet_state.json; do
  if [[ -f "$TMP_DIR/$f" ]]; then
    cp "$TMP_DIR/$f" "$TARGET_DIR/$f"
    echo "Restored: $TARGET_DIR/$f"
  fi
done

if [[ -f "$TMP_DIR/env.live" ]]; then
  cp "$TMP_DIR/env.live" "$(dirname "$TARGET_DIR")/.env.live.restored"
  echo "Restored env to: $(dirname "$TARGET_DIR")/.env.live.restored"
fi

echo "Restore complete."
