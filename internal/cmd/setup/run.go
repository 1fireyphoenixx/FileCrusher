// Package setup implements the "filecrusher setup" CLI subcommand.
// It forwards CLI options to the underlying setup workflow.
package setup

import (
	"context"
	"flag"

	isetup "filecrusher/internal/setup"
)

// Options captures CLI flags for initial setup.
// AdminPassword and AdminPasswordEnv are mutually exclusive by usage.
type Options struct {
	DBPath           string
	DataDir          string
	AdminPassword    string
	AdminPasswordEnv bool
	RegenTLS         bool
}

// Run parses setup flags and executes the setup workflow.
// The setup operation initializes the database and key material.
func Run(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	var opt Options
	fs.StringVar(&opt.DBPath, "db", "./filecrusher.db", "sqlite database path")
	fs.StringVar(&opt.DataDir, "data-dir", "./data", "data directory (keys/certs)")
	fs.StringVar(&opt.AdminPassword, "admin-password", "", "set initial admin password non-interactively")
	fs.BoolVar(&opt.AdminPasswordEnv, "admin-password-env", false, "read initial admin password from FILECRUSHER_ADMIN_PASSWORD")
	fs.BoolVar(&opt.RegenTLS, "regen-tls", false, "overwrite tls.crt/tls.key in data-dir")
	if err := fs.Parse(args); err != nil {
		return err
	}

	return isetup.Run(context.Background(), isetup.Options{
		DBPath:           opt.DBPath,
		DataDir:          opt.DataDir,
		AdminPassword:    opt.AdminPassword,
		AdminPasswordEnv: opt.AdminPasswordEnv,
		RegenTLS:         opt.RegenTLS,
	})
}
