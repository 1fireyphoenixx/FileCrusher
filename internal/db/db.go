// Package db wraps SQLite access and schema migrations.
// It centralizes database configuration and connection health checks.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a sql.DB and provides higher-level helpers.
type DB struct {
	sql *sql.DB
}

// Open creates a SQLite connection, applies pragmas, and runs migrations.
// The returned DB is ready for use by other packages.
func Open(ctx context.Context, path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("db path is required")
	}

	// modernc SQLite uses a URI-like DSN; plain file paths are ok.
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)", path)
	s, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	s.SetMaxOpenConns(1)
	s.SetMaxIdleConns(1)
	s.SetConnMaxLifetime(0)

	db := &DB{sql: s}
	if err := db.ping(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := db.setPragmas(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := Migrate(ctx, s); err != nil {
		_ = s.Close()
		return nil, err
	}

	return db, nil
}

// Close releases the underlying database connection.
func (d *DB) Close() error {
	return d.sql.Close()
}

// ping verifies the connection is usable within a short timeout.
func (d *DB) ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return d.sql.PingContext(ctx)
}

// setPragmas applies SQLite settings optimized for this service.
func (d *DB) setPragmas(ctx context.Context) error {
	// WAL improves read concurrency for web + transfers.
	_, err := d.sql.ExecContext(ctx, "PRAGMA journal_mode = WAL;")
	if err != nil {
		return err
	}
	// Wait briefly instead of failing immediately on SQLITE_BUSY.
	if _, err := d.sql.ExecContext(ctx, "PRAGMA busy_timeout = 5000;"); err != nil {
		return err
	}
	// Reasonable tradeoff for WAL mode on typical deployments.
	if _, err := d.sql.ExecContext(ctx, "PRAGMA synchronous = NORMAL;"); err != nil {
		return err
	}
	_, err = d.sql.ExecContext(ctx, "PRAGMA foreign_keys = ON;")
	return err
}
