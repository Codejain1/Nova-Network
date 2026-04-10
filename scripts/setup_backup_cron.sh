#!/usr/bin/env bash
# ── Nova Network — Backup Cron Setup ──────────────────────────────────────
# Sets up a daily cron job to backup the Docker volume data.
# Usage: ./scripts/setup_backup_cron.sh [backup-dir]
set -euo pipefail

BACKUP_DIR="${1:-/opt/nova-backups}"
RETENTION_DAYS=7

echo "Setting up Nova Network daily backup..."
echo "  Backup directory: $BACKUP_DIR"
echo "  Retention: ${RETENTION_DAYS} days"
echo ""

mkdir -p "$BACKUP_DIR"

# Create the backup script
BACKUP_SCRIPT="/usr/local/bin/nova-backup.sh"
cat > "$BACKUP_SCRIPT" << 'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="__BACKUP_DIR__"
RETENTION_DAYS=__RETENTION_DAYS__
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/nova_data_${TIMESTAMP}.tar.gz"

# Find the Docker volume mount
VOLUME_PATH=$(docker volume inspect nova_main_data --format '{{.Mountpoint}}' 2>/dev/null \
  || docker volume inspect nova_validator_data --format '{{.Mountpoint}}' 2>/dev/null \
  || echo "")

if [[ -z "$VOLUME_PATH" ]]; then
  echo "ERROR: No Nova Docker volume found" >&2
  exit 1
fi

# Create compressed backup
tar czf "$BACKUP_FILE" -C "$(dirname "$VOLUME_PATH")" "$(basename "$VOLUME_PATH")"
echo "Backup created: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"

# Prune old backups
find "$BACKUP_DIR" -name "nova_data_*.tar.gz" -mtime +"$RETENTION_DAYS" -delete
echo "Pruned backups older than ${RETENTION_DAYS} days"
SCRIPT

sed -i "s|__BACKUP_DIR__|${BACKUP_DIR}|g" "$BACKUP_SCRIPT"
sed -i "s|__RETENTION_DAYS__|${RETENTION_DAYS}|g" "$BACKUP_SCRIPT"
chmod +x "$BACKUP_SCRIPT"

# Add cron job (daily at 3 AM)
CRON_LINE="0 3 * * * $BACKUP_SCRIPT >> ${BACKUP_DIR}/backup.log 2>&1"
(crontab -l 2>/dev/null | grep -v nova-backup; echo "$CRON_LINE") | crontab -

echo "Cron job installed (daily at 3:00 AM)"
echo "  Script: $BACKUP_SCRIPT"
echo "  Log:    ${BACKUP_DIR}/backup.log"
echo ""
echo "Test it now: sudo $BACKUP_SCRIPT"
