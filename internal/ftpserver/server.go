// Package ftpserver implements FTP and FTPS servers backed by FileCrusher users.
package ftpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
	"filecrusher/internal/jailfs"
	ftp "github.com/fclairamb/ftpserverlib"
)

// Mode selects FTP vs FTPS behavior.
type Mode int

const (
	ModeFTP Mode = iota + 1
	ModeFTPS
	ModeFTPSImplicit
)

var errAccessDenied = errors.New("access denied")

// Options configures server address, TLS, and feature flags.
type Options struct {
	Addr           string
	DB             *db.DB
	Mode           Mode
	TLSConfig      *tls.Config
	PassivePorts   *ftp.PortRange
	PublicHostIP   string
	DisableMLSD    bool
	IdleTimeoutSec int
	Logger         *slog.Logger
}

// ListenAndServe starts an FTP or FTPS server until the context is done.
func ListenAndServe(ctx context.Context, opt Options) error {
	if opt.DB == nil {
		return errors.New("db is required")
	}
	if opt.Addr == "" {
		return errors.New("addr is required")
	}
	if opt.Mode != ModeFTP && opt.Mode != ModeFTPS && opt.Mode != ModeFTPSImplicit {
		return errors.New("invalid mode")
	}
	if (opt.Mode == ModeFTPS || opt.Mode == ModeFTPSImplicit) && opt.TLSConfig == nil {
		return errors.New("tls config is required for FTPS")
	}

	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return err
	}
	if opt.Mode == ModeFTPSImplicit {
		ln = tls.NewListener(ln, opt.TLSConfig)
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	drv := &mainDriver{db: opt.DB, mode: opt.Mode, tlsConfig: opt.TLSConfig, passive: opt.PassivePorts, publicHost: opt.PublicHostIP, disableMLSD: opt.DisableMLSD, idleTimeout: opt.IdleTimeoutSec, listener: ln}
	srv := ftp.NewFtpServer(drv)
	if opt.Logger != nil {
		srv.Logger = opt.Logger
	}
	return srv.ListenAndServe()
}

// mainDriver connects ftpserverlib callbacks to FileCrusher storage.
type mainDriver struct {
	db          *db.DB
	mode        Mode
	tlsConfig   *tls.Config
	passive     ftp.PasvPortGetter
	publicHost  string
	disableMLSD bool
	idleTimeout int
	listener    net.Listener
}

// GetSettings returns server settings for ftpserverlib.
func (d *mainDriver) GetSettings() (*ftp.Settings, error) {
	idle := d.idleTimeout
	if idle == 0 {
		idle = 300
	}

	tlsReq := ftp.ClearOrEncrypted
	switch d.mode {
	case ModeFTPS:
		tlsReq = ftp.MandatoryEncryption
	case ModeFTPSImplicit:
		tlsReq = ftp.ImplicitEncryption
	}

	s := &ftp.Settings{
		Listener:                 d.listener,
		ListenAddr:               "",
		Banner:                   "FileCrusher",
		PassiveTransferPortRange: d.passive,
		PublicHost:               d.publicHost,
		IdleTimeout:              idle,
		ConnectionTimeout:        15,
		DisableActiveMode:        true,
		TLSRequired:              tlsReq,
		DisableMLSD:              d.disableMLSD,
		ActiveConnectionsCheck:   ftp.IPMatchRequired,
		PasvConnectionsCheck:     ftp.IPMatchRequired,
	}
	return s, nil
}

// ClientConnected returns a banner string for new connections.
func (d *mainDriver) ClientConnected(cc ftp.ClientContext) (string, error) {
	_ = cc
	return "FileCrusher ready", nil
}

// ClientDisconnected is a hook for connection cleanup.
func (d *mainDriver) ClientDisconnected(cc ftp.ClientContext) {
	_ = cc
}

func (d *mainDriver) AuthUser(cc ftp.ClientContext, user, pass string) (ftp.ClientDriver, error) {
	ctx := context.Background()
	u, ok, err := d.db.GetUserByUsername(ctx, user)
	if err != nil || !ok || !u.Enabled {
		auth.DummyVerify(pass)
		return nil, errors.New("invalid credentials")
	}
	if d.mode == ModeFTP && !u.AllowFTP {
		auth.DummyVerify(pass)
		return nil, errAccessDenied
	}
	if d.mode == ModeFTPS && !u.AllowFTPS {
		auth.DummyVerify(pass)
		return nil, errAccessDenied
	}

	okPw, err := auth.VerifyPassword(pass, u.PassHash)
	if err != nil || !okPw {
		return nil, errors.New("invalid credentials")
	}

	cc.SetPath("/")
	return jailfs.New(u.RootPath), nil
}

// GetTLSConfig provides TLS settings for FTPS and optional TLS in FTP.
func (d *mainDriver) GetTLSConfig() (*tls.Config, error) {
	if d.tlsConfig == nil {
		return nil, errors.New("tls not configured")
	}
	// Important: return the same *tls.Config instance for both control and data
	// connections so clients can verify TLS session resumption/reuse.
	return d.tlsConfig, nil
}

// PreAuthUser is called on the FTP USER command before PASS.
// It MUST always succeed to avoid leaking whether a username exists
// (user enumeration). The real auth check happens in AuthUser.
func (d *mainDriver) PreAuthUser(cc ftp.ClientContext, user string) error {
	// Enforce TLS before proceeding in explicit-FTPS mode.
	// For implicit FTPS, the control channel is already TLS at accept time.
	if d.mode == ModeFTPS {
		_ = cc.SetTLSRequirement(ftp.MandatoryEncryption)
	}
	return nil
}

// Compile-time interface assertions.
var _ ftp.MainDriver = (*mainDriver)(nil)
var _ ftp.MainDriverExtensionUserVerifier = (*mainDriver)(nil)
