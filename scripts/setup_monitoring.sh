#!/usr/bin/env bash
# ── Nova Network — Monitoring Setup ────────────────────────────────────────
# Sets up a cron-based health monitor that alerts on failure.
# Usage: ./scripts/setup_monitoring.sh [webhook-url]
# Supports: Slack webhook, Discord webhook, or just logs to file.
set -euo pipefail

WEBHOOK_URL="${1:-}"
CHECK_INTERVAL=5  # minutes
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MONITOR_SCRIPT="/usr/local/bin/nova-monitor.sh"
LOG_FILE="/var/log/nova-monitor.log"

echo "Setting up Nova Network health monitoring..."

cat > "$MONITOR_SCRIPT" << 'SCRIPT'
#!/usr/bin/env bash
set -uo pipefail

MAIN_URL="${MAIN_URL:-https://explorer.flowpe.io}"
VAL1_URL="${VAL1_URL:-http://84.32.108.5:8000}"
VAL2_URL="${VAL2_URL:-http://84.32.108.10:8000}"
WEBHOOK_URL="__WEBHOOK_URL__"
LOG_FILE="__LOG_FILE__"
HOSTNAME="$(hostname)"

alert() {
  local msg="$1"
  local ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "[$ts] ALERT: $msg" >> "$LOG_FILE"

  if [[ -n "$WEBHOOK_URL" ]]; then
    local payload="{\"text\":\"[Nova $HOSTNAME] $msg\"}"
    # Works with both Slack and Discord webhooks
    curl -sf -X POST -H "Content-Type: application/json" -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1 || true
  fi
}

check_node() {
  local name="$1" url="$2"
  local resp
  resp=$(curl -sf -m 10 "$url/health" 2>/dev/null) || {
    alert "$name ($url) is DOWN - health check failed"
    return 1
  }
  echo "$(date -u +%H:%M:%S) $name: OK" >> "$LOG_FILE"
}

# Check chain is advancing
check_chain_progress() {
  local status height
  status=$(curl -sf -m 10 "$MAIN_URL/status" 2>/dev/null) || return 1
  height=$(echo "$status" | python3 -c "import sys,json; print(json.load(sys.stdin).get('public_height',0))" 2>/dev/null)

  local cache_file="/tmp/nova_last_height"
  if [[ -f "$cache_file" ]]; then
    local last_height=$(cat "$cache_file")
    if [[ "$height" -le "$last_height" ]]; then
      alert "Chain stalled at height $height (no new blocks in last check interval)"
    fi
  fi
  echo "$height" > "$cache_file"
}

check_node "main-node" "$MAIN_URL"
check_node "validator-1" "$VAL1_URL"
check_node "validator-2" "$VAL2_URL"
check_chain_progress
SCRIPT

sed -i "s|__WEBHOOK_URL__|${WEBHOOK_URL}|g" "$MONITOR_SCRIPT"
sed -i "s|__LOG_FILE__|${LOG_FILE}|g" "$MONITOR_SCRIPT"
chmod +x "$MONITOR_SCRIPT"
touch "$LOG_FILE"

# Add cron job
CRON_LINE="*/${CHECK_INTERVAL} * * * * $MONITOR_SCRIPT"
(crontab -l 2>/dev/null | grep -v nova-monitor; echo "$CRON_LINE") | crontab -

echo "Monitor installed (every ${CHECK_INTERVAL} minutes)"
echo "  Script:  $MONITOR_SCRIPT"
echo "  Log:     $LOG_FILE"
if [[ -n "$WEBHOOK_URL" ]]; then
  echo "  Webhook: ${WEBHOOK_URL:0:40}..."
else
  echo "  Webhook: none (log-only mode)"
  echo "  Add Slack/Discord webhook: $0 <webhook-url>"
fi
echo ""
echo "Test it now: sudo $MONITOR_SCRIPT && tail $LOG_FILE"
