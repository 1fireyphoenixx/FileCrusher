package server

import (
	"context"
	"flag"

	"filecrusher/internal/daemon"
)

type Options struct {
	DBPath   string
	DataDir  string
	BindAddr string
	WebPort  int
	SFTPPort int
}

func Run(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	var opt Options
	fs.StringVar(&opt.DBPath, "db", "./filecrusher.db", "sqlite database path")
	fs.StringVar(&opt.DataDir, "data-dir", "./data", "data directory (keys/certs)")
	fs.StringVar(&opt.BindAddr, "bind", "127.0.0.1", "bind address")
	fs.IntVar(&opt.WebPort, "web-port", 5132, "web/admin HTTPS port")
	fs.IntVar(&opt.SFTPPort, "sftp-port", 2022, "SFTP SSH port")
	if err := fs.Parse(args); err != nil {
		return err
	}

	return daemon.Run(context.Background(), daemon.Options{
		DBPath:   opt.DBPath,
		DataDir:  opt.DataDir,
		BindAddr: opt.BindAddr,
		WebPort:  opt.WebPort,
		SFTPPort: opt.SFTPPort,
	})
}
