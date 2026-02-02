// Package db contains database query helpers for FileCrusher.
package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// nowUnix returns the current Unix timestamp in seconds.
func nowUnix() int64 { return time.Now().Unix() }

// GetConfig fetches a single config key from the database.
// The boolean indicates whether the key exists.
func (d *DB) GetConfig(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := d.sql.QueryRowContext(ctx, "SELECT value FROM config WHERE key = ?", key).Scan(&v)
	if err == nil {
		return v, true, nil
	}
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return "", false, err
}

// SetConfig upserts a config key/value pair and updates its timestamp.
func (d *DB) SetConfig(ctx context.Context, key, value string) error {
	if key == "" {
		return errors.New("config key is required")
	}
	_, err := d.sql.ExecContext(ctx, `
INSERT INTO config(key, value, updated_at) VALUES(?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
`, key, value, nowUnix())
	return err
}

// IsInitialized reports whether setup has completed.
func (d *DB) IsInitialized(ctx context.Context) (bool, error) {
	v, ok, err := d.GetConfig(ctx, "initialized")
	if err != nil {
		return false, err
	}
	return ok && v == "1", nil
}

// SetInitialized marks the database as setup-complete.
func (d *DB) SetInitialized(ctx context.Context) error {
	return d.SetConfig(ctx, "initialized", "1")
}

// GetAdminPasswordHash returns the stored admin password hash.
func (d *DB) GetAdminPasswordHash(ctx context.Context) (string, bool, error) {
	return d.GetConfig(ctx, "admin_password_hash")
}

// SetAdminPasswordHash stores the admin password hash.
func (d *DB) SetAdminPasswordHash(ctx context.Context, hash string) error {
	return d.SetConfig(ctx, "admin_password_hash", hash)
}

// CreateUser inserts a new user and returns its database ID.
func (d *DB) CreateUser(ctx context.Context, username, passHash, rootPath string, allowSFTP, allowFTP, allowFTPS, allowSCP, allowWebDAV bool) (int64, error) {
	if username == "" || passHash == "" || rootPath == "" {
		return 0, errors.New("username, password hash, and root path are required")
	}
	res, err := d.sql.ExecContext(ctx, `
INSERT INTO users(username, password_hash, root_path, enabled, allow_sftp, allow_ftp, allow_ftps, allow_scp, allow_webdav, created_at, updated_at)
VALUES(?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
`, username, passHash, rootPath, boolToInt(allowSFTP), boolToInt(allowFTP), boolToInt(allowFTPS), boolToInt(allowSCP), boolToInt(allowWebDAV), nowUnix(), nowUnix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateUser updates mutable user fields and protocol permissions.
func (d *DB) UpdateUser(ctx context.Context, id int64, rootPath string, enabled, allowSFTP, allowFTP, allowFTPS, allowSCP, allowWebDAV bool) error {
	if id <= 0 {
		return errors.New("invalid user id")
	}
	_, err := d.sql.ExecContext(ctx, `
UPDATE users SET root_path=?, enabled=?, allow_sftp=?, allow_ftp=?, allow_ftps=?, allow_scp=?, allow_webdav=?, updated_at=? WHERE id=?
`, rootPath, boolToInt(enabled), boolToInt(allowSFTP), boolToInt(allowFTP), boolToInt(allowFTPS), boolToInt(allowSCP), boolToInt(allowWebDAV), nowUnix(), id)
	return err
}

// SetUserPasswordHash updates a user's password hash.
func (d *DB) SetUserPasswordHash(ctx context.Context, id int64, passHash string) error {
	if id <= 0 {
		return errors.New("invalid user id")
	}
	if passHash == "" {
		return errors.New("password hash is required")
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE users SET password_hash=?, updated_at=? WHERE id=?`, passHash, nowUnix(), id)
	return err
}

// DeleteUser removes a user by ID.
func (d *DB) DeleteUser(ctx context.Context, id int64) error {
	if id <= 0 {
		return errors.New("invalid user id")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

// GetUserByUsername looks up a user by username.
func (d *DB) GetUserByUsername(ctx context.Context, username string) (*User, bool, error) {
	var u User
	var enabled, allowSFTP, allowFTP, allowFTPS, allowSCP, allowWebDAV int
	err := d.sql.QueryRowContext(ctx, `
SELECT id, username, password_hash, root_path, enabled, allow_sftp, allow_ftp, allow_ftps, allow_scp, allow_webdav, created_at, updated_at
FROM users WHERE username=?
`, username).Scan(&u.ID, &u.Username, &u.PassHash, &u.RootPath, &enabled, &allowSFTP, &allowFTP, &allowFTPS, &allowSCP, &allowWebDAV, &u.CreatedAt, &u.UpdatedAt)
	if err == nil {
		u.Enabled = enabled != 0
		u.AllowSFTP = allowSFTP != 0
		u.AllowFTP = allowFTP != 0
		u.AllowFTPS = allowFTPS != 0
		u.AllowSCP = allowSCP != 0
		u.AllowWebDAV = allowWebDAV != 0
		return &u, true, nil
	}
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	return nil, false, err
}

// GetUserByID looks up a user by ID.
func (d *DB) GetUserByID(ctx context.Context, id int64) (*User, bool, error) {
	var u User
	var enabled, allowSFTP, allowFTP, allowFTPS, allowSCP, allowWebDAV int
	err := d.sql.QueryRowContext(ctx, `
SELECT id, username, password_hash, root_path, enabled, allow_sftp, allow_ftp, allow_ftps, allow_scp, allow_webdav, created_at, updated_at
FROM users WHERE id=?
`, id).Scan(&u.ID, &u.Username, &u.PassHash, &u.RootPath, &enabled, &allowSFTP, &allowFTP, &allowFTPS, &allowSCP, &allowWebDAV, &u.CreatedAt, &u.UpdatedAt)
	if err == nil {
		u.Enabled = enabled != 0
		u.AllowSFTP = allowSFTP != 0
		u.AllowFTP = allowFTP != 0
		u.AllowFTPS = allowFTPS != 0
		u.AllowSCP = allowSCP != 0
		u.AllowWebDAV = allowWebDAV != 0
		return &u, true, nil
	}
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	return nil, false, err
}

// ListUsers returns all users sorted by username.
func (d *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := d.sql.QueryContext(ctx, `
SELECT id, username, password_hash, root_path, enabled, allow_sftp, allow_ftp, allow_ftps, allow_scp, allow_webdav, created_at, updated_at
FROM users ORDER BY username ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		var enabled, allowSFTP, allowFTP, allowFTPS, allowSCP, allowWebDAV int
		if err := rows.Scan(&u.ID, &u.Username, &u.PassHash, &u.RootPath, &enabled, &allowSFTP, &allowFTP, &allowFTPS, &allowSCP, &allowWebDAV, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.Enabled = enabled != 0
		u.AllowSFTP = allowSFTP != 0
		u.AllowFTP = allowFTP != 0
		u.AllowFTPS = allowFTPS != 0
		u.AllowSCP = allowSCP != 0
		u.AllowWebDAV = allowWebDAV != 0
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// AddSSHKey stores a new SSH key for a user.
func (d *DB) AddSSHKey(ctx context.Context, userID int64, publicKey, fingerprint, comment string) (int64, error) {
	if userID <= 0 {
		return 0, errors.New("invalid user id")
	}
	if publicKey == "" || fingerprint == "" {
		return 0, errors.New("public key and fingerprint are required")
	}
	res, err := d.sql.ExecContext(ctx, `
INSERT INTO ssh_keys(user_id, public_key, fingerprint, comment, created_at)
VALUES(?, ?, ?, ?, ?)
`, userID, publicKey, fingerprint, comment, nowUnix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListSSHKeysForUser returns all SSH keys for a user.
func (d *DB) ListSSHKeysForUser(ctx context.Context, userID int64) ([]SSHKey, error) {
	rows, err := d.sql.QueryContext(ctx, `
SELECT id, user_id, public_key, fingerprint, comment, created_at
FROM ssh_keys WHERE user_id=? ORDER BY id ASC
`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SSHKey
	for rows.Next() {
		var k SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.PublicKey, &k.Fingerprint, &k.Comment, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DeleteSSHKey removes an SSH key by its ID.
func (d *DB) DeleteSSHKey(ctx context.Context, id int64) error {
	if id <= 0 {
		return errors.New("invalid key id")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM ssh_keys WHERE id=?`, id)
	return err
}

// DeleteSSHKeyForUser deletes a specific SSH key for a user.
func (d *DB) DeleteSSHKeyForUser(ctx context.Context, userID, keyID int64) error {
	if userID <= 0 || keyID <= 0 {
		return errors.New("invalid id")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM ssh_keys WHERE id=? AND user_id=?`, keyID, userID)
	return err
}

// CreateSession inserts a new session token with expiration.
func (d *DB) CreateSession(ctx context.Context, token, kind string, subjectID int64, ttl time.Duration) error {
	if token == "" || kind == "" || subjectID <= 0 {
		return errors.New("invalid session")
	}
	now := nowUnix()
	_, err := d.sql.ExecContext(ctx, `
INSERT INTO sessions(token, kind, subject_id, created_at, expires_at)
VALUES(?, ?, ?, ?, ?)
`, token, kind, subjectID, now, now+int64(ttl.Seconds()))
	return err
}

// GetSession looks up a session by token.
func (d *DB) GetSession(ctx context.Context, token string) (*Session, bool, error) {
	var s Session
	err := d.sql.QueryRowContext(ctx, `
SELECT token, kind, subject_id, created_at, expires_at FROM sessions WHERE token=?
`, token).Scan(&s.Token, &s.Kind, &s.SubjectID, &s.CreatedAt, &s.ExpiresAt)
	if err == nil {
		return &s, true, nil
	}
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	return nil, false, err
}

// DeleteSession removes a session by token.
func (d *DB) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("token is required")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE token=?`, token)
	return err
}

// DeleteExpiredSessions deletes sessions that have expired.
func (d *DB) DeleteExpiredSessions(ctx context.Context, nowUnix int64) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, nowUnix)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListAdminIPAllowlist returns all admin allowlist entries.
func (d *DB) ListAdminIPAllowlist(ctx context.Context) ([]AdminIPAllowEntry, error) {
	rows, err := d.sql.QueryContext(ctx, `
SELECT id, cidr, COALESCE(note, ''), created_at
FROM admin_ip_allowlist
ORDER BY id ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AdminIPAllowEntry
	for rows.Next() {
		var e AdminIPAllowEntry
		if err := rows.Scan(&e.ID, &e.CIDR, &e.Note, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddAdminIPAllowlist inserts a new admin allowlist entry.
func (d *DB) AddAdminIPAllowlist(ctx context.Context, cidr, note string) (int64, error) {
	if cidr == "" {
		return 0, errors.New("cidr is required")
	}
	res, err := d.sql.ExecContext(ctx, `INSERT INTO admin_ip_allowlist(cidr, note, created_at) VALUES(?, ?, ?)`, cidr, note, nowUnix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteAdminIPAllowlist removes an allowlist entry by ID.
func (d *DB) DeleteAdminIPAllowlist(ctx context.Context, id int64) error {
	if id <= 0 {
		return errors.New("invalid id")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM admin_ip_allowlist WHERE id=?`, id)
	return err
}

// boolToInt maps booleans to SQLite-friendly integer flags.
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
