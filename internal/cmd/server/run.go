package server

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"filecrusher/internal/config"
	"filecrusher/internal/daemon"
	"filecrusher/internal/version"
)

type Options struct {
	ConfigPath string

	DBPath          string
	DataDir         string
	BindAddr        string
	WebPort         int
	SFTPPort        int
	FTPEnable       bool
	FTPPort         int
	FTPSEnable      bool
	FTPSPort        int
	FTPPassivePorts string
	FTPPublicHost   string
}

func Run(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	var opt Options
	var showVersion bool
	fs.StringVar(&opt.ConfigPath, "config", "", "path to filecrusher.yaml (when set, flags are ignored)")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&opt.DBPath, "db", "./filecrusher.db", "sqlite database path")
	fs.StringVar(&opt.DataDir, "data-dir", "./data", "data directory (keys/certs)")
	fs.StringVar(&opt.BindAddr, "bind", "127.0.0.1", "bind address")
	fs.IntVar(&opt.WebPort, "web-port", 5132, "web/admin HTTPS port")
	fs.IntVar(&opt.SFTPPort, "sftp-port", 2022, "SFTP SSH port")
	fs.BoolVar(&opt.FTPEnable, "ftp-enable", false, "enable plain FTP (insecure; prefer FTPS)")
	fs.IntVar(&opt.FTPPort, "ftp-port", 2121, "FTP control port")
	fs.BoolVar(&opt.FTPSEnable, "ftps-enable", false, "enable explicit FTPS")
	fs.IntVar(&opt.FTPSPort, "ftps-port", 2122, "FTPS control port")
	fs.StringVar(&opt.FTPPassivePorts, "ftp-passive-ports", "50000-50100", "passive data port range start-end")
	fs.StringVar(&opt.FTPPublicHost, "ftp-public-host", "", "public IP to advertise in PASV responses")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if showVersion {
		fmt.Printf("filecrusher server %s\n", version.Version)
		return nil
	}

	if opt.ConfigPath != "" {
		c, err := config.Load(opt.ConfigPath)
		if err != nil {
			return err
		}
		base := filepath.Dir(opt.ConfigPath)
		return daemon.Run(context.Background(), daemon.Options{
			DBPath:          resolvePath(base, c.DB.Path),
			DataDir:         resolvePath(base, c.DataDir),
			BindAddr:        c.HTTP.Bind,
			WebPort:         c.HTTP.Port,
			SFTPPort:        c.SSH.Port,
			FTPEnable:       c.FTP.Enable,
			FTPPort:         c.FTP.Port,
			FTPSEnable:      c.FTPS.Enable,
			FTPSPort:        c.FTPS.Port,
			FTPPassivePorts: firstNonEmpty(c.FTPS.PassivePorts, c.FTP.PassivePorts),
			FTPPublicHost:   firstNonEmpty(c.FTPS.PublicHost, c.FTP.PublicHost),
			TLSCertPath:     resolvePath(base, c.HTTP.TLS.CertPath),
			TLSKeyPath:      resolvePath(base, c.HTTP.TLS.KeyPath),
			SSHHostKeyPath:  resolvePath(base, c.SSH.HostKeyPath),
		})
	}

	return daemon.Run(context.Background(), daemon.Options{
		DBPath:          opt.DBPath,
		DataDir:         opt.DataDir,
		BindAddr:        opt.BindAddr,
		WebPort:         opt.WebPort,
		SFTPPort:        opt.SFTPPort,
		FTPEnable:       opt.FTPEnable,
		FTPPort:         opt.FTPPort,
		FTPSEnable:      opt.FTPSEnable,
		FTPSPort:        opt.FTPSPort,
		FTPPassivePorts: opt.FTPPassivePorts,
		FTPPublicHost:   opt.FTPPublicHost,
	})
}

func resolvePath(baseDir, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}

func firstNonEmpty(a, b string) string {
	a = strings.TrimSpace(a)
	if a != "" {
		return a
	}
	return strings.TrimSpace(b)
}
