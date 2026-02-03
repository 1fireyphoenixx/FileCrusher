// Package daemon coordinates all FileCrusher services.
// It loads config from the database and starts HTTP, SFTP, FTP, and FTPS servers.
package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"filecrusher/internal/db"
	"filecrusher/internal/ftpserver"
	"filecrusher/internal/httpapi"
	"filecrusher/internal/sftpserver"
	ftp "github.com/fclairamb/ftpserverlib"
)

// Options configures the daemon runtime.
// Optional TLS/SSH paths override values stored in the database.
type Options struct {
	DBPath   string
	DataDir  string
	BindAddr string
	WebPort  int
	SFTPPort int

	// Optional overrides. If empty, values are read from DB config (set by `setup`).
	TLSCertPath    string
	TLSKeyPath     string
	SSHHostKeyPath string

	Logger         *slog.Logger
	MaxUploadBytes int64

	FTPEnable       bool
	FTPExplicitTLS  bool
	FTPPort         int
	FTPSEnable      bool
	FTPSPort        int
	FTPSImplicitEnable bool
	FTPSImplicitPort   int
	FTPPassivePorts string
	FTPPublicHost   string

	WebDAVEnable bool
	WebDAVPrefix string
}

// Run validates options, loads stored configuration, and starts servers.
// It blocks until the first server returns an error.
func Run(ctx context.Context, opt Options) error {
	if opt.DBPath == "" {
		return errors.New("db path is required")
	}
	lg := opt.Logger
	if lg == nil {
		lg = slog.Default()
	}
	d, err := db.Open(ctx, opt.DBPath)
	if err != nil {
		return err
	}
	defer d.Close()
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// Periodically prune expired sessions to keep the DB small.
				if n, err := d.DeleteExpiredSessions(ctx, time.Now().Unix()); err == nil {
					if n > 0 {
						lg.Debug("pruned expired sessions", "deleted", n)
					}
				}
			}
		}
	}()
	initialized, err := d.IsInitialized(ctx)
	if err != nil {
		return err
	}
	if !initialized {
		return errors.New("not initialized; run setup")
	}

	certPath := strings.TrimSpace(opt.TLSCertPath)
	keyPath := strings.TrimSpace(opt.TLSKeyPath)
	if certPath == "" || keyPath == "" {
		v, ok, err := d.GetConfig(ctx, "tls_cert_path")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("missing tls cert config; run setup")
		}
		certPath = v
		v, ok, err = d.GetConfig(ctx, "tls_key_path")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("missing tls key config; run setup")
		}
		keyPath = v
	}

	hostKeyPath := strings.TrimSpace(opt.SSHHostKeyPath)
	if hostKeyPath == "" {
		v, ok, err := d.GetConfig(ctx, "ssh_host_key_path")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("missing ssh host key config; run setup")
		}
		hostKeyPath = v
	}

	api := &httpapi.Server{
		DB:             d,
		BindAddr:       opt.BindAddr,
		Port:           opt.WebPort,
		CertPath:       certPath,
		KeyPath:        keyPath,
		Logger:         lg,
		MaxUploadBytes: opt.MaxUploadBytes,
		WebDAVEnable:   opt.WebDAVEnable,
		WebDAVPrefix:   opt.WebDAVPrefix,
	}

	// Buffer for HTTP, SFTP, FTP, FTPS, implicit FTPS.
	errCh := make(chan error, 5)
	go func() {
		addr := opt.BindAddr + ":" + strconv.Itoa(opt.SFTPPort)
		errCh <- sftpserver.ListenAndServe(ctx, sftpserver.Options{Addr: addr, DB: d, HostKeyPath: hostKeyPath, Logger: lg})
	}()
	go func() { errCh <- api.ListenAndServeTLS() }()

	passive, err := parsePortRange(opt.FTPPassivePorts)
	if err != nil {
		return err
	}

	var tlsConf *tls.Config
	if opt.FTPExplicitTLS || opt.FTPSEnable || opt.FTPSImplicitEnable {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
		tlsConf = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	}

	if opt.FTPEnable {
		addr := opt.BindAddr + ":" + strconv.Itoa(opt.FTPPort)
		ftpTLS := (*tls.Config)(nil)
		if opt.FTPExplicitTLS {
			ftpTLS = tlsConf
		}
		go func() {
			errCh <- ftpserver.ListenAndServe(ctx, ftpserver.Options{Addr: addr, DB: d, Mode: ftpserver.ModeFTP, TLSConfig: ftpTLS, PassivePorts: passive, PublicHostIP: opt.FTPPublicHost, Logger: lg})
		}()
	}
	if opt.FTPSEnable {
		addr := opt.BindAddr + ":" + strconv.Itoa(opt.FTPSPort)
		go func() {
			errCh <- ftpserver.ListenAndServe(ctx, ftpserver.Options{Addr: addr, DB: d, Mode: ftpserver.ModeFTPS, TLSConfig: tlsConf, PassivePorts: passive, PublicHostIP: opt.FTPPublicHost, Logger: lg})
		}()
	}
	if opt.FTPSImplicitEnable {
		addr := opt.BindAddr + ":" + strconv.Itoa(opt.FTPSImplicitPort)
		go func() {
			errCh <- ftpserver.ListenAndServe(ctx, ftpserver.Options{Addr: addr, DB: d, Mode: ftpserver.ModeFTPSImplicit, TLSConfig: tlsConf, PassivePorts: passive, PublicHostIP: opt.FTPPublicHost, Logger: lg})
		}()
	}

	return <-errCh
}

// parsePortRange converts "start-end" into a PortRange.
// An empty string returns nil to let the FTP server choose ephemeral ports.
func parsePortRange(s string) (*ftp.PortRange, error) {
	// Format: start-end. Empty disables range (server chooses ephemeral ports).
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return nil, errors.New("invalid ftp-passive-ports")
	}
	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, errors.New("invalid ftp-passive-ports")
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, errors.New("invalid ftp-passive-ports")
	}
	if start <= 0 || end <= 0 || end < start {
		return nil, errors.New("invalid ftp-passive-ports")
	}
	pr := &ftp.PortRange{Start: start, End: end}
	return pr, nil
}
