<div align="center">
  <h1>🗜️ FileCrusher</h1>
  <p><b>A high-performance, single-binary file sharing server.</b></p>
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go" alt="Go Version" />
</div>

<br />

**FileCrusher** is a standalone, lightweight server designed to handle file sharing across multiple protocols with zero external dependencies. It includes a built-in HTTPS Web UI, a terminal user interface (TUI) for administration, and supports modern and legacy file transfer protocols out of the box.

---

## ✨ Features

- **🌐 HTTPS Server**: Integrated Web UI and Admin API running on `:5132`.
- **🖥️ Admin TUI**: A beautiful terminal interface for user and server management.
- **🔐 Secure Shell (SSH)**: Built-in SFTP and SCP support (default `:2022`).
- **📁 Legacy Protocols**: Optional FTP and FTPS servers for broader compatibility.
- **☁️ WebDAV**: Seamless mounting over HTTPS.
- **📦 Single Binary**: SQLite storage for users, SSH keys, sessions, and configuration. No database setup required.

---

## 🚀 Quick Start

Get FileCrusher up and running in seconds.

```bash
# 1. Build the binary
go build -o filecrusher ./cmd/filecrusher

# 2. Run initial setup (creates sqlite DB and generates TLS certs)
./filecrusher setup --db ./data/filecrusher.db --data-dir ./data

# 3. Prepare your configuration
cp filecrusher.example.yaml filecrusher.yaml

# 4. Start the server
./filecrusher server --config ./filecrusher.yaml

# 5. Access the Admin TUI (in a new terminal)
./filecrusher admin --addr https://127.0.0.1:5132
```

---

## ⚙️ Configuration

FileCrusher is configured via a minimal `filecrusher.yaml` file. 

<details>
<summary><b>View Example Configuration</b></summary>

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
  # Optional. If empty, server uses paths stored by `filecrusher setup` in sqlite.
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
</details>

### CLI Overrides
You can override configurations via command-line flags:
- `filecrusher server --config ./filecrusher.yaml` (config-first)
- `filecrusher server --log-level debug|info|warning|error` (overrides config)
- `filecrusher server --version`

---

## 🛠️ Admin Operations

FileCrusher provides robust admin tools for managing your server seamlessly.

### Initial Setup
The admin password is **never** stored in your YAML configuration.
- **Interactive:** `./filecrusher setup --db ./data/filecrusher.db --data-dir ./data`
- **Non-interactive:**
  - `./filecrusher setup --admin-password '...'`
  - `FILECRUSHER_ADMIN_PASSWORD=... ./filecrusher setup --admin-password-env`

*Forgot your password?* Reset or rotate it directly from the SQLite DB:
`./filecrusher reset-admin --db ./data/filecrusher.db`

### 💻 Admin TUI
Connect to the interactive terminal UI:
```bash
./filecrusher admin --addr https://127.0.0.1:5132
```
**Shortcuts (Users Screen):**
- `n` New User | `e` Edit | `d` Delete | `p` Set Password
- `k` Manage SSH Keys
- `w` Manage Admin IP Allowlist

### 🛡️ Admin IP Allowlist
Control who can access the admin endpoints:
- **Default:** If empty, access is restricted to loopback (localhost) only.
- **Configured:** If entries exist, only matching IP/CIDRs can access admin endpoints (including login).
- **Shortcuts:** `alt+a` (Add CIDR/IP), `alt+d` (Delete selected).

---

## 🕸️ Web UI & Protocols

### Web UI
Access the user-facing web interface by browsing to:
`https://127.0.0.1:5132/`

### File Transfer Protocols
Per-user protocol permissions are managed directly in the Admin TUI.

| Protocol | Default Port | Status | Description |
|----------|-------------|---------|-------------|
| **SSH** | `:2022` | Enabled | Supports SFTP (subsystem) and SCP (non-recursive exec). |
| **FTP** | `:2121` | Disabled | Plaintext FTP (enable via config). |
| **FTPS** | `:2122` | Enabled | Explicit TLS FTP. |
| **WebDAV** | `:5132` | Disabled | Mountable WebDAV over HTTPS. |

#### WebDAV
Runs over the same HTTPS port as the Web UI. When enabled (`webdav.enable: true`), mount your drive at:
```text
https://your-server:5132/webdav/
```
*Uses HTTP Basic Auth. Compatible with Windows Explorer, macOS Finder, Linux file managers, `cadaver`, `rclone`, etc.*

---

## 🔒 Security Behavior

FileCrusher is built with safety in mind:
- **Upload Limits:** Configurable via `http.max_upload_mb` (default `512 MiB` per request).
- **Payload Limits:** JSON body limit strictly capped at `64 KiB`.
- **Safety Checks:** Refuses HTTP `DELETE` operations on `/` (user root).
- **Rate Limiting:** Protects both Admin and User login endpoints.
- **Session Management:** Expired sessions are periodically pruned.

### Managing TLS Certificates (HTTPS + FTPS)

FileCrusher uses a single TLS cert/key pair for both Web/Admin HTTPS and FTPS.
By default, `setup` generates a self-signed cert in your `--data-dir` (e.g., `./data/tls.crt`).

**To use your own certificates:**
1. Update `http.tls.cert_path` and `http.tls.key_path` in `filecrusher.yaml`.
2. Restart the server.

*(Alternatively, overwrite the files at the existing paths.)*

> **Troubleshooting:** If you see `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`, regenerate your self-signed cert:
> `./filecrusher setup --db ./data/filecrusher.db --data-dir ./data --regen-tls`

---

## 📦 Deployment

### Systemd Service

A sample unit file (`filecrusher.service`) is provided.

<details>
<summary><b>Show systemd setup instructions</b></summary>

```bash
# 1. Create service user
sudo useradd -r -s /sbin/nologin filecrusher

# 2. Install binary and config
sudo mkdir -p /opt/filecrusher/data
sudo cp filecrusher /opt/filecrusher/
sudo cp filecrusher.yaml /opt/filecrusher/
sudo chown -R filecrusher:filecrusher /opt/filecrusher

# 3. Run initial setup
sudo -u filecrusher /opt/filecrusher/filecrusher setup \
  --db /opt/filecrusher/data/filecrusher.db \
  --data-dir /opt/filecrusher/data

# 4. Install and enable service
sudo cp filecrusher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now filecrusher

# 5. Check status
sudo systemctl status filecrusher
sudo journalctl -u filecrusher -f
```
</details>

### Reverse Proxies

FileCrusher can sit behind a reverse proxy for load balancing or centralized TLS termination. FileCrusher reads `X-Forwarded-For` for rate limiting. 

> **Note:** For SSH/SFTP/FTP protocols, ensure your load balancer is using TCP mode or handle them separately. If terminating TLS at the proxy, bind FileCrusher to `127.0.0.1` in your config.

<details>
<summary><b>HAProxy Example</b></summary>

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
</details>

<details>
<summary><b>Nginx Example</b></summary>

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
```
</details>
