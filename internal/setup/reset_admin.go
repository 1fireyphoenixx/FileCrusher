package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
)

type ResetAdminOptions struct {
	DBPath           string
	AdminPassword    string
	AdminPasswordEnv bool
}

func ResetAdmin(ctx context.Context, opt ResetAdminOptions) error {
	if opt.DBPath == "" {
		return errors.New("db path is required")
	}
	if err := os.MkdirAll(filepath.Dir(opt.DBPath), 0o700); err != nil {
		return err
	}

	d, err := db.Open(ctx, opt.DBPath)
	if err != nil {
		return err
	}
	defer d.Close()

	initialized, err := d.IsInitialized(ctx)
	if err != nil {
		return err
	}
	if !initialized {
		return errors.New("not initialized; run setup")
	}

	pass, err := resolveAdminPassword("Set admin password", opt.AdminPassword, opt.AdminPasswordEnv)
	if err != nil {
		return err
	}

	h, err := auth.HashPassword(pass, auth.DefaultArgon2Params())
	if err != nil {
		return err
	}
	return d.SetAdminPasswordHash(ctx, h)
}

func resolveAdminPassword(label string, flagValue string, fromEnv bool) (string, error) {
	if flagValue != "" && fromEnv {
		return "", errors.New("choose one of --admin-password or --admin-password-env")
	}
	if fromEnv {
		v := strings.TrimSpace(os.Getenv("FILECRUSHER_ADMIN_PASSWORD"))
		if v == "" {
			return "", errors.New("FILECRUSHER_ADMIN_PASSWORD is empty")
		}
		return v, nil
	}
	if flagValue != "" {
		v := strings.TrimSpace(flagValue)
		if v == "" {
			return "", errors.New("admin password is empty")
		}
		return v, nil
	}
	return promptPassword(label)
}
