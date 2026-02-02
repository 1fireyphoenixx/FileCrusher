# FileCrusher

Single-binary file sharing server.

Included:
- HTTPS server on `:5132` (Web UI + Admin API)
- Admin TUI client (connects to `:5132`)
- SFTP + SCP on SSH (`:2022` by default)
- Optional FTP/FTPS servers
- SQLite storage (users, SSH keys, sessions, config)

## Quick start

```bash
go build -o filecrusher ./cmd/filecrusher

./filecrusher setup --db ./data/filecrusher.db --data-dir ./data
cp filecrusher.example.yaml filecrusher.yaml
./filecrusher server --config ./filecrusher.yaml

./filecrusher admin --addr https://127.0.0.1:5132
```

## Configuration

Runtime config is `filecrusher.yaml` (minimal on purpose). Use `filecrusher.example.yaml` as a template.

```yaml
log:
  level: "info" # info | warning | error | debug

db:
  path: "./data/filecrusher.db"

data_dir: "./data"

http:
  bind: "127.0.0.1"
  port: 5132
  max_upload_mb: 512
  tls:
    # Optional. If empty, server uses paths stored by `filecrusher setup` in sqlite.
    cert_path: ""
    key_path: ""

ssh:
  bind: "127.0.0.1"
  port: 2022
  # Optional. If empty, server uses path stored by `filecrusher setup` in sqlite.
  host_key_path: ""

ftp:
  enable: false
  port: 2121
  passive_ports: "50000-50100"
  public_host: ""

ftps:
  enable: true
  port: 2122
  passive_ports: "50000-50100"
  public_host: ""

webdav:
  enable: false
  prefix: "/webdav"
```

CLI flags:
- `filecrusher server --config ./filecrusher.yaml` (config-first)
- `filecrusher server --log-level debug|info|warning|error` (overrides config)
- `filecrusher server --version`

## Admin operations

Initial setup (admin password is never stored in YAML):
- Interactive: `./filecrusher setup --db ./data/filecrusher.db --data-dir ./data`
- Non-interactive:
  - `./filecrusher setup --admin-password '...'`
  - `FILECRUSHER_ADMIN_PASSWORD=... ./filecrusher setup --admin-password-env`

Reset/rotate admin password (local command, edits sqlite):
- `./filecrusher reset-admin --db ./data/filecrusher.db`

Admin TUI:
- Connect: `./filecrusher admin --addr https://127.0.0.1:5132`
- Users screen keys:
  - `n` new user, `e` edit, `d` delete, `p` set password
  - `k` manage SSH keys
  - `w` manage admin IP allowlist

Admin IP allowlist:
- Default behavior: if allowlist is empty, admin access is loopback-only.
- If allowlist has entries, only matching IP/CIDR can use admin endpoints (including admin login).
- In the allowlist screen:
  - `alt+a` add CIDR/IP
  - `alt+d` delete selected

## Web UI

Browse to `https://127.0.0.1:5132/`.

## Protocols

Per-user protocol permissions are managed in the admin TUI:
- SFTP (SSH subsystem)
- SCP (SSH exec, non-recursive)
- FTP / FTPS
- WebDAV (over HTTPS)

Defaults:
- SSH (SFTP/SCP): `:2022`
- FTP: disabled by default
- FTPS: enabled/disabled via config
- WebDAV: disabled by default (enable with `webdav.enable: true`)

### WebDAV

WebDAV runs over the same HTTPS port as the Web UI. When enabled, mount at:
```
https://your-server:5132/webdav/
```

Uses HTTP Basic Auth with user credentials. Works with:
- Windows Explorer (Map Network Drive)
- macOS Finder (Connect to Server)
- Linux file managers (Nautilus, Dolphin)
- `cadaver`, `rclone`, etc.

## Security behavior

- Upload limit: configurable via `http.max_upload_mb` (default 512 MiB) per request.
- JSON body limit: 64 KiB.
- Web delete safety: refuses `DELETE` of `/` (user root).
- Rate limiting:
  - admin login and admin endpoints
  - user login
- Sessions: expired sessions are periodically pruned.

## Changing TLS certs (HTTPS + FTPS)

FileCrusher uses a single TLS certificate/key pair for:
- HTTPS Web/Admin on `http.port`
- FTPS (explicit TLS)

By default, `filecrusher setup` generates a self-signed cert and writes it to your `--data-dir` (typically `./data/tls.crt` and `./data/tls.key`). The SQLite DB stores the file paths.

To change the cert/key:
1. Config override (recommended): set `http.tls.cert_path` and `http.tls.key_path` in `filecrusher.yaml`, then restart `filecrusher server`.
2. Replace-in-place: overwrite the existing `./data/tls.crt` and `./data/tls.key` files (or whatever paths your DB points to), then restart.

If you generated certs previously and your browser reports `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`, regenerate the self-signed cert with:
`./filecrusher setup --db ./data/filecrusher.db --data-dir ./data --regen-tls`

## Deployment

### systemd

A sample unit file is provided in `filecrusher.service`. To install:

```bash
# Create service user
sudo useradd -r -s /sbin/nologin filecrusher

# Install binary and config
sudo mkdir -p /opt/filecrusher/data
sudo cp filecrusher /opt/filecrusher/
sudo cp filecrusher.yaml /opt/filecrusher/
sudo chown -R filecrusher:filecrusher /opt/filecrusher

# Run initial setup
sudo -u filecrusher /opt/filecrusher/filecrusher setup \
  --db /opt/filecrusher/data/filecrusher.db \
  --data-dir /opt/filecrusher/data

# Install and enable service
sudo cp filecrusher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now filecrusher

# Check status
sudo systemctl status filecrusher
sudo journalctl -u filecrusher -f
```

### Reverse proxy (HAProxy)

FileCrusher serves HTTPS directly but can sit behind a reverse proxy for load balancing, centralized TLS termination, or additional security headers.

**HAProxy example** (`/etc/haproxy/haproxy.cfg`):

```haproxy
global
    maxconn 4096
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    mode http
    timeout connect 10s
    timeout client 60s
    timeout server 60s
    timeout http-request 10s

frontend https_in
    bind *:443 ssl crt /etc/haproxy/certs/filecrusher.pem
    
    # Security headers (HAProxy adds these; FileCrusher also sets them)
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options DENY
    http-response set-header Referrer-Policy no-referrer
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    
    # Forward to FileCrusher backend
    default_backend filecrusher

backend filecrusher
    option httpchk GET /
    http-check expect status 200
    
    # Pass client IP to FileCrusher
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Proto https
    
    # FileCrusher backend (HTTPS passthrough or HTTP if TLS terminated at HAProxy)
    server fc1 127.0.0.1:5132 ssl verify none check
```

**Notes:**
- FileCrusher reads `X-Forwarded-For` for rate limiting when behind a proxy.
- For SSH/SFTP/FTP protocols, use TCP mode or separate load balancers.
- If terminating TLS at HAProxy, configure FileCrusher to bind to localhost only.

### Nginx reverse proxy

```nginx
upstream filecrusher {
    server 127.0.0.1:5132;
}

server {
    listen 443 ssl http2;
    server_name files.example.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Security headers
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Increase for large uploads
    client_max_body_size 512M;
    
    location / {
        proxy_pass https://filecrusher;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebDAV support
        proxy_pass_request_headers on;
        proxy_set_header Destination $http_destination;
    }
}
