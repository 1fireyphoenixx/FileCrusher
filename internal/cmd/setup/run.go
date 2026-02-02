package setup

import (
	"context"
	"flag"

	isetup "filecrusher/internal/setup"
)

type Options struct {
	DBPath  string
	DataDir string
}

func Run(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	var opt Options
	fs.StringVar(&opt.DBPath, "db", "./filecrusher.db", "sqlite database path")
	fs.StringVar(&opt.DataDir, "data-dir", "./data", "data directory (keys/certs)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	return isetup.Run(context.Background(), isetup.Options{
		DBPath:  opt.DBPath,
		DataDir: opt.DataDir,
	})
}
