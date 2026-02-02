CREATE TABLE IF NOT EXISTS admin_ip_allowlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cidr TEXT NOT NULL,
  note TEXT,
  created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_ip_allowlist_cidr ON admin_ip_allowlist(cidr);
