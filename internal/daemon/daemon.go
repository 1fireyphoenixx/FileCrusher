package daemon

import (
	"context"
	"errors"
	"strconv"

	"filecrusher/internal/db"
	"filecrusher/internal/httpapi"
	"filecrusher/internal/sftpserver"
)

type Options struct {
	DBPath   string
	DataDir  string
	BindAddr string
	WebPort  int
	SFTPPort int
}

func Run(ctx context.Context, opt Options) error {
	if opt.DBPath == "" {
		return errors.New("db path is required")
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

	certPath, ok, err := d.GetConfig(ctx, "tls_cert_path")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("missing tls cert config; run setup")
	}
	keyPath, ok, err := d.GetConfig(ctx, "tls_key_path")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("missing tls key config; run setup")
	}
	hostKeyPath, ok, err := d.GetConfig(ctx, "ssh_host_key_path")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("missing ssh host key config; run setup")
	}

	api := &httpapi.Server{
		DB:       d,
		BindAddr: opt.BindAddr,
		Port:     opt.WebPort,
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	errCh := make(chan error, 2)
	go func() {
		addr := opt.BindAddr + ":" + strconv.Itoa(opt.SFTPPort)
		errCh <- sftpserver.ListenAndServe(ctx, sftpserver.Options{Addr: addr, DB: d, HostKeyPath: hostKeyPath})
	}()
	go func() { errCh <- api.ListenAndServeTLS() }()

	return <-errCh
}
