package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func nowUnix() int64 { return time.Now().Unix() }

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

func (d *DB) IsInitialized(ctx context.Context) (bool, error) {
	v, ok, err := d.GetConfig(ctx, "initialized")
	if err != nil {
		return false, err
	}
	return ok && v == "1", nil
}

func (d *DB) SetInitialized(ctx context.Context) error {
	return d.SetConfig(ctx, "initialized", "1")
}

func (d *DB) GetAdminPasswordHash(ctx context.Context) (string, bool, error) {
	return d.GetConfig(ctx, "admin_password_hash")
}

func (d *DB) SetAdminPasswordHash(ctx context.Context, hash string) error {
	return d.SetConfig(ctx, "admin_password_hash", hash)
}

func (d *DB) CreateUser(ctx context.Context, username, passHash, rootPath string, allowSFTP, allowFTP, allowFTPS, allowSCP bool) (int64, error) {
	if username == "" || passHash == "" || rootPath == "" {
		return 0, errors.New("username, password hash, and root path are required")
	}
	res, err := d.sql.ExecContext(ctx, `
INSERT INTO users(username, password_hash, root_path, enabled, allow_sftp, allow_ftp, allow_ftps, allow_scp, created_at, updated_at)
VALUES(?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
`, username, passHash, rootPath, boolToInt(allowSFTP), boolToInt(allowFTP), boolToInt(allowFTPS), boolToInt(allowSCP), nowUnix(), nowUnix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) UpdateUser(ctx context.Context, id int64, rootPath string, enabled, allowSFTP, allowFTP, allowFTPS, allowSCP bool) error {
	if id <= 0 {
		return errors.New("invalid user id")
	}
	_, err := d.sql.ExecContext(ctx, `
UPDATE users SET root_path=?, enabled=?, allow_sftp=?, allow_ftp=?, allow_ftps=?, allow_scp=?, updated_at=? WHERE id=?
`, rootPath, boolToInt(enabled), boolToInt(allowSFTP), boolToInt(allowFTP), boolToInt(allowFTPS), boolToInt(allowSCP), nowUnix(), id)
	return err
}

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

func (d *DB) DeleteUser(ctx context.Context, id int64) error {
	if id <= 0 {
		return errors.New("invalid user id")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

func (d *DB) GetUserByUsername(ctx context.Context, username string) (*User, bool, error) {
	var u User
	var enabled, allowSFTP, allowFTP, allowFTPS, allowSCP int
	err := d.sql.QueryRowContext(ctx, `
SELECT id, username, password_hash, root_path, enabled, allow_sftp, allow_ftp, allow_ftps, allow_scp, created_at, updated_at
FROM users WHERE username=?
`, username).Scan(&u.ID, &u.Username, &u.PassHash, &u.RootPath, &enabled, &allowSFTP, &allowFTP, &allowFTPS, &allowSCP, &u.CreatedAt, &u.UpdatedAt)
	if err == nil {
		u.Enabled = enabled != 0
		u.AllowSFTP = allowSFTP != 0
		u.AllowFTP = allowFTP != 0
		u.AllowFTPS = allowFTPS != 0
		u.AllowSCP = allowSCP != 0
		return &u, true, nil
	}
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	return nil, false, err
}

func (d *DB) GetUserByID(ctx context.Context, id int64) (*User, bool, error) {
	var u User
	var enabled, allowSFTP, allowFTP, allowFTPS, allowSCP int
	err := d.sql.QueryRowContext(ctx, `
SELECT id, username, password_hash, root_path, enabled, allow_sftp, allow_ftp, allow_ftps, allow_scp, created_at, updated_at
FROM users WHERE id=?
`, id).Scan(&u.ID, &u.Username, &u.PassHash, &u.RootPath, &enabled, &allowSFTP, &allowFTP, &allowFTPS, &allowSCP, &u.CreatedAt, &u.UpdatedAt)
	if err == nil {
		u.Enabled = enabled != 0
		u.AllowSFTP = allowSFTP != 0
		u.AllowFTP = allowFTP != 0
		u.AllowFTPS = allowFTPS != 0
		u.AllowSCP = allowSCP != 0
		return &u, true, nil
	}
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	return nil, false, err
}

func (d *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := d.sql.QueryContext(ctx, `
SELECT id, username, password_hash, root_path, enabled, allow_sftp, allow_ftp, allow_ftps, allow_scp, created_at, updated_at
FROM users ORDER BY username ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		var enabled, allowSFTP, allowFTP, allowFTPS, allowSCP int
		if err := rows.Scan(&u.ID, &u.Username, &u.PassHash, &u.RootPath, &enabled, &allowSFTP, &allowFTP, &allowFTPS, &allowSCP, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.Enabled = enabled != 0
		u.AllowSFTP = allowSFTP != 0
		u.AllowFTP = allowFTP != 0
		u.AllowFTPS = allowFTPS != 0
		u.AllowSCP = allowSCP != 0
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

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

func (d *DB) DeleteSSHKey(ctx context.Context, id int64) error {
	if id <= 0 {
		return errors.New("invalid key id")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM ssh_keys WHERE id=?`, id)
	return err
}

func (d *DB) DeleteSSHKeyForUser(ctx context.Context, userID, keyID int64) error {
	if userID <= 0 || keyID <= 0 {
		return errors.New("invalid id")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM ssh_keys WHERE id=? AND user_id=?`, keyID, userID)
	return err
}

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

func (d *DB) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("token is required")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE token=?`, token)
	return err
}

func (d *DB) DeleteExpiredSessions(ctx context.Context, nowUnix int64) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, nowUnix)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

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

func (d *DB) DeleteAdminIPAllowlist(ctx context.Context, id int64) error {
	if id <= 0 {
		return errors.New("invalid id")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM admin_ip_allowlist WHERE id=?`, id)
	return err
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
