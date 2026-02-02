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
