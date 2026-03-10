# Upgrading FileCrusher

## Quick Upgrade (all versions)

```bash
# 1. Stop the server.
systemctl stop filecrusher        # systemd
# docker compose down             # Docker

# 2. Back up your database (recommended).
cp /opt/filecrusher/data/filecrusher.db /opt/filecrusher/data/filecrusher.db.bak

# 3. Replace the binary.
cp filecrusher-linux-amd64 /opt/filecrusher/filecrusher
chmod +x /opt/filecrusher/filecrusher

# 4. Start the server.
systemctl start filecrusher
# docker compose up -d
```

Database migrations run **automatically** on startup. If a migration fails
the server will refuse to start and log the error — your backup is untouched.

No manual SQL, no migration commands, no config changes required between
patch releases within the same minor version.

---

## How Migrations Work

Every FileCrusher release embeds its database migrations. On startup the
server:

1. Opens the SQLite database.
2. Compares embedded migration files against the `schema_migrations` table.
3. Applies any unapplied migrations inside a transaction.
4. Records the migration hash so it is never re-applied.

If step 3 fails the transaction rolls back and the server exits with an
error. The database remains in its pre-upgrade state.

---

## Version History

### 1.3.0

- Added `http.theme` config option (`simple` or `modern`).
- Added `filecrusher config generate` subcommand.
- Added Docker, Compose, and Kubernetes deployment manifests.
- No database schema changes.

### 1.2.x

- **Migration 005** — Adds `allow_webdav` column to `users` (default: disabled).
- Introduced WebDAV support.

### 1.1.x

- **Migration 004** — Creates `admin_ip_allowlist` table.
- Admin API access can be restricted by CIDR.

### 1.0.x

- **Migration 002** — Adds `allow_ftp`, `allow_ftps`, `allow_scp` columns
  to `users` (default: disabled).
- FTP/FTPS/SCP protocol support.

### 0.x (initial)

- **Migration 001** — Creates `config`, `users`, `ssh_keys`, `sessions`
  tables.

> Migration 003 was removed before release and is intentionally absent.

---

## Downgrading

FileCrusher does not provide automatic rollback. To downgrade:

```bash
systemctl stop filecrusher
cp /opt/filecrusher/data/filecrusher.db.bak /opt/filecrusher/data/filecrusher.db
# Replace binary with the older version.
systemctl start filecrusher
```

Older binaries ignore columns added by newer migrations — they will run
but will not manage fields they do not know about (e.g., `allow_webdav`
is invisible to a 1.0.x binary). This is safe for temporary rollbacks but
you should re-upgrade promptly.

---

## Docker Upgrades

```bash
# Pull or rebuild the new image.
docker compose build --pull
# or: docker compose pull  (if using a registry image)

# Recreate the container. The named volume persists across recreations.
docker compose up -d
```

The entrypoint script detects an existing database and skips setup
automatically. Migrations run on startup just like a bare-metal install.

---

## Kubernetes Upgrades

Update the container image tag in your StatefulSet manifest and apply:

```bash
kubectl set image statefulset/filecrusher \
  filecrusher=ghcr.io/yourorg/filecrusher:1.3.0 \
  -n filecrusher

# Or edit the manifest and apply:
kubectl apply -f deploy/kubernetes/filecrusher.yaml
```

The PersistentVolumeClaim survives pod restarts. Migrations run
automatically when the new pod starts.

---

## Troubleshooting

### Server won't start after upgrade

Check the logs for a migration error:

```bash
journalctl -u filecrusher --no-pager -n 50   # systemd
docker compose logs --tail 50                 # Docker
```

Common causes:

| Symptom | Cause | Fix |
|---------|-------|-----|
| `database is locked` | Another process has the DB open | Stop all FileCrusher processes, retry |
| `disk full` | Not enough space for migration | Free disk space, restart |
| `not initialized; run setup` | DB file missing or empty | Restore from backup or re-run setup |

### Need a fresh start

```bash
systemctl stop filecrusher
rm /opt/filecrusher/data/filecrusher.db
filecrusher setup --db /opt/filecrusher/data/filecrusher.db \
                  --data-dir /opt/filecrusher/data
systemctl start filecrusher
```

This recreates the database and admin credentials. TLS and SSH keys in the
data directory are preserved unless you pass `--regen-tls`.
