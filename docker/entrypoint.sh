#!/usr/bin/env bash
# Ragnar container entrypoint: prepare runtime state, then exec the app.
set -e

cd /opt/ragnar

# Persisted directories may arrive as empty bind mounts — make sure they exist.
mkdir -p data config certs data/logs data/output

# Seed runtime data files from their tracked *.template versions (idempotent —
# existing files are never overwritten).
if [ -f scripts/init_data_files.sh ]; then
    bash scripts/init_data_files.sh || true
elif [ -f init_data_files.sh ]; then
    bash init_data_files.sh || true
fi

echo "[ragnar] starting headless web UI on port ${RAGNAR_WEB_PORT:-8000}"
exec "$@"
