# FileCrusher

Single-binary file sharing server (staged build).

Phase 1 goals:
- SFTP server (password + SSH public key auth)
- HTTPS server on :5132 (Web UI + Admin API)
- Admin TUI client that talks to :5132
- SQLite storage for users/keys/sessions/config

## Quick start (planned)

```bash
go build ./cmd/filecrusher

./filecrusher setup --db ./data/filecrusher.db --data-dir ./data
cp filecrusher.example.yaml filecrusher.yaml
./filecrusher server --config ./filecrusher.yaml

./filecrusher admin --addr https://127.0.0.1:5132
```

Notes:
- `filecrusher.yaml` is intentionally minimal; most secrets (admin password) are never stored in config.
- TLS/SSH key paths can be provided in `filecrusher.yaml`, or omitted to use the paths written by `setup` into the sqlite config table.

## Changing TLS certs (HTTPS + FTPS)

FileCrusher uses a single TLS certificate/key pair for:
- HTTPS Web/Admin on `http.port`
- FTPS (explicit TLS)

By default, `filecrusher setup` generates a self-signed cert and writes it to your `--data-dir` (typically `./data/tls.crt` and `./data/tls.key`). The SQLite DB stores the file paths.

To change the cert/key:
1. Config override (recommended): set `http.tls.cert_path` and `http.tls.key_path` in `filecrusher.yaml`, then restart `filecrusher server`.
2. Replace-in-place: overwrite the existing `./data/tls.crt` and `./data/tls.key` files (or whatever paths your DB points to), then restart.
