#!/bin/sh
set -e

DB_PATH="${FILECRUSHER_DB_PATH:-/data/filecrusher.db}"
DATA_DIR="${FILECRUSHER_DATA_DIR:-/data}"

if [ ! -f "$DB_PATH" ]; then
    echo "[entrypoint] first boot — running setup"

    if [ -z "$FILECRUSHER_ADMIN_PASSWORD" ]; then
        echo "[entrypoint] FILECRUSHER_ADMIN_PASSWORD must be set on first boot" >&2
        exit 1
    fi

    /usr/local/bin/filecrusher setup \
        --db "$DB_PATH" \
        --data-dir "$DATA_DIR" \
        --admin-password-env

    echo "[entrypoint] setup complete"
fi

if [ ! -f /etc/filecrusher/filecrusher.yaml ]; then
    echo "[entrypoint] generating default config"
    /usr/local/bin/filecrusher config generate > /etc/filecrusher/filecrusher.yaml
fi

exec /usr/local/bin/filecrusher "$@"
