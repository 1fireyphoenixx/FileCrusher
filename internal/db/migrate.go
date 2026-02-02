package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func Migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at INTEGER NOT NULL
);
`); err != nil {
		return err
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".sql") {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}

		id := migrationID(name, body)
		applied, err := isMigrationApplied(ctx, db, id)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		if err := applyMigration(ctx, db, id, string(body)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}

	return nil
}

func migrationID(name string, body []byte) string {
	h := sha256.Sum256(body)
	return name + ":" + hex.EncodeToString(h[:])
}

func isMigrationApplied(ctx context.Context, db *sql.DB, id string) (bool, error) {
	var v string
	err := db.QueryRowContext(ctx, "SELECT id FROM schema_migrations WHERE id = ?", id).Scan(&v)
	if err == nil {
		return true, nil
	}
	if err == sql.ErrNoRows {
		return false, nil
	}
	return false, err
}

func applyMigration(ctx context.Context, db *sql.DB, id string, sqlText string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, sqlText); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(id, applied_at) VALUES(?, strftime('%s','now'))", id); err != nil {
		return err
	}

	return tx.Commit()
}
