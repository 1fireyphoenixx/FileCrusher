// Package resetadmin implements the "filecrusher reset-admin" CLI subcommand.
// It resets the admin password directly in the SQLite database.
package resetadmin

import (
	"context"
	"flag"

	isetup "filecrusher/internal/setup"
)

// Options captures CLI flags for admin password reset.
// AdminPassword and AdminPasswordEnv are mutually exclusive by usage.
type Options struct {
	DBPath           string
	AdminPassword    string
	AdminPasswordEnv bool
}

// Run parses reset-admin flags and executes the password reset workflow.
// The reset is local-only and does not require the server to be running.
func Run(args []string) error {
	fs := flag.NewFlagSet("reset-admin", flag.ContinueOnError)
	var opt Options
	fs.StringVar(&opt.DBPath, "db", "./filecrusher.db", "sqlite database path")
	fs.StringVar(&opt.AdminPassword, "admin-password", "", "set admin password non-interactively")
	fs.BoolVar(&opt.AdminPasswordEnv, "admin-password-env", false, "read admin password from FILECRUSHER_ADMIN_PASSWORD")
	if err := fs.Parse(args); err != nil {
		return err
	}

	return isetup.ResetAdmin(context.Background(), isetup.ResetAdminOptions{
		DBPath:           opt.DBPath,
		AdminPassword:    opt.AdminPassword,
		AdminPasswordEnv: opt.AdminPasswordEnv,
	})
}
