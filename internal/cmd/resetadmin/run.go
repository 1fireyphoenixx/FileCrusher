package resetadmin

import (
	"context"
	"flag"

	isetup "filecrusher/internal/setup"
)

type Options struct {
	DBPath           string
	AdminPassword    string
	AdminPasswordEnv bool
}

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
