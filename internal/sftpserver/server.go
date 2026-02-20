// Package sftpserver provides SSH-based SFTP and SCP services.
package sftpserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
	"filecrusher/internal/scpserver"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Options configures the SFTP/SCP listener.
type Options struct {
	Addr        string
	DB          *db.DB
	HostKeyPath string
	Logger      *slog.Logger
}

// ListenAndServe starts an SSH server that handles SFTP and SCP.
func ListenAndServe(ctx context.Context, opt Options) error {
	if opt.DB == nil {
		return errors.New("db is required")
	}
	if opt.Addr == "" {
		return errors.New("addr is required")
	}
	if opt.HostKeyPath == "" {
		return errors.New("host key path is required")
	}

	lg := opt.Logger
	if lg == nil {
		lg = slog.Default()
	}

	hostSigner, err := loadSigner(opt.HostKeyPath)
	if err != nil {
		return err
	}

	conf := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			u, ok, err := opt.DB.GetUserByUsername(ctx, c.User())
			if err != nil || !ok || !u.Enabled || (!u.AllowSFTP && !u.AllowSCP) {
				auth.DummyVerify(string(pass))
				return nil, errors.New("invalid credentials")
			}
			okPw, err := auth.VerifyPassword(string(pass), u.PassHash)
			if err != nil || !okPw {
				return nil, errors.New("invalid credentials")
			}
			return &ssh.Permissions{Extensions: map[string]string{"user_id": intToString(u.ID)}}, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			u, ok, err := opt.DB.GetUserByUsername(ctx, c.User())
			if err != nil || !ok || !u.Enabled || (!u.AllowSFTP && !u.AllowSCP) {
				return nil, errors.New("invalid credentials")
			}
			fp := ssh.FingerprintSHA256(key)
			keys, err := opt.DB.ListSSHKeysForUser(ctx, u.ID)
			if err != nil {
				return nil, errors.New("invalid credentials")
			}
			for _, k := range keys {
				if k.Fingerprint == fp {
					return &ssh.Permissions{Extensions: map[string]string{"user_id": intToString(u.ID)}}, nil
				}
			}
			return nil, errors.New("invalid credentials")
		},
	}
	conf.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return err
	}
	lg.Info("sftp/scp listening", "addr", opt.Addr)
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return err
		}
		lg.Debug("ssh connection accepted", "remote", c.RemoteAddr().String())
		go handleConn(opt.DB, conf, c, lg)
	}
}

// handleConn completes the SSH handshake and serves channels.
func handleConn(d *db.DB, conf *ssh.ServerConfig, netConn net.Conn, lg *slog.Logger) {
	defer netConn.Close()
	_ = netConn.SetDeadline(time.Now().Add(30 * time.Second))
	serverConn, chans, reqs, err := ssh.NewServerConn(netConn, conf)
	if err != nil {
		lg.Warn("ssh handshake failed", "remote", netConn.RemoteAddr().String())
		return
	}
	defer serverConn.Close()
	_ = netConn.SetDeadline(time.Time{})

	go ssh.DiscardRequests(reqs)

	u, ok, err := d.GetUserByUsername(context.Background(), serverConn.User())
	if err != nil || !ok {
		return
	}
	root := u.RootPath
	lg.Info("ssh authenticated", "user", u.Username, "remote", serverConn.RemoteAddr().String(), "allow_sftp", u.AllowSFTP, "allow_scp", u.AllowSCP)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range reqs {
				if req.Type == "subsystem" {
					if len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
						if !u.AllowSFTP {
							lg.Warn("sftp denied", "user", u.Username)
							_ = req.Reply(false, nil)
							return
						}
						lg.Debug("sftp start", "user", u.Username)
						_ = req.Reply(true, nil)
						h := JailedHandlers{Root: root}
						s := sftp.NewRequestServer(ch, sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h})
						_ = s.Serve()
						return
					}
				}
				if req.Type == "exec" {
					var payload struct {
						Command string
					}
					if err := ssh.Unmarshal(req.Payload, &payload); err == nil {
						if u.AllowSCP && scpserver.CanHandle(payload.Command) {
							lg.Debug("scp exec", "user", u.Username, "cmd", payload.Command)
							_ = req.Reply(true, nil)
							_ = scpserver.HandleExec(ch, root, payload.Command)
							return
						}
					}
				}
				_ = req.Reply(false, nil)
			}
		}()
	}
}

// loadSigner reads and parses the SSH host key file.
func loadSigner(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

// intToString converts an int64 to its decimal string form.
func intToString(v int64) string {
	return strconv.FormatInt(v, 10)
}
