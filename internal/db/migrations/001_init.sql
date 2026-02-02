PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  root_path TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  allow_sftp INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  comment TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_user_id ON ssh_keys(user_id);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  subject_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
