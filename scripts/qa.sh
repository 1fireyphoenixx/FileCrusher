#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QA_DIR="$ROOT/.qa"
BIN="$QA_DIR/filecrusher"
DB="$QA_DIR/filecrusher.db"
DATA="$QA_DIR/data"
CONFIG="$QA_DIR/filecrusher.yaml"
ADMIN_PASS="admin"
WEB_PORT=5132
SFTP_PORT=2022

cleanup() {
    echo ""
    echo "shutting down..."
    [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
    echo "done"
}
trap cleanup EXIT INT TERM

echo "=== FileCrusher QA ==="
echo ""

# ── Build ────────────────────────────────────────────────────────────────────
echo "[1/4] building..."
(cd "$ROOT" && go build -o "$BIN" ./cmd/filecrusher)
echo "      $BIN"

# ── Data dir ─────────────────────────────────────────────────────────────────
mkdir -p "$DATA"

# ── Setup (first run only) ───────────────────────────────────────────────────
if [ ! -f "$DB" ]; then
    echo "[2/4] running first-time setup..."
    FILECRUSHER_ADMIN_PASSWORD="$ADMIN_PASS" \
        "$BIN" setup --db "$DB" --data-dir "$DATA" --admin-password-env
else
    echo "[2/4] setup already done (rm $QA_DIR to reset)"
fi

# ── Config ───────────────────────────────────────────────────────────────────
echo "[3/4] writing config..."
cat > "$CONFIG" <<EOF
log:
  level: "debug"
db:
  path: "$DB"
data_dir: "$DATA"
http:
  bind: "127.0.0.1"
  port: $WEB_PORT
  max_upload_mb: 512
  theme: "modern"
  tls:
    cert_path: ""
    key_path: ""
ssh:
  port: $SFTP_PORT
  host_key_path: ""
ftp:
  enable: false
ftps:
  enable: false
ftps_implicit:
  enable: false
webdav:
  enable: true
  prefix: "/webdav"
EOF

# ── Start ────────────────────────────────────────────────────────────────────
echo "[4/4] starting server..."
echo ""
echo "  Web UI   https://127.0.0.1:$WEB_PORT"
echo "  Admin    $BIN admin --addr https://127.0.0.1:$WEB_PORT --insecure"
echo "  SFTP     sftp -P $SFTP_PORT -o StrictHostKeyChecking=no user@127.0.0.1"
echo "  WebDAV   https://127.0.0.1:$WEB_PORT/webdav"
echo ""
echo "  admin password: $ADMIN_PASS"
echo "  data dir:       $QA_DIR"
echo "  config:         $CONFIG"
echo ""
echo "  Ctrl-C to stop"
echo ""

"$BIN" server --config "$CONFIG" &
PID=$!
wait "$PID"
