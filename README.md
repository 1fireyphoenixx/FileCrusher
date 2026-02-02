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
./filecrusher server --db ./data/filecrusher.db --data-dir ./data

./filecrusher admin --addr https://127.0.0.1:5132
```
