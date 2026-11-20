package sftpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sshFixture struct {
	db     *db.DB
	config *ssh.ServerConfig
	host   ssh.PublicKey
	root   string
	userID int64
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newSSHFixture(t *testing.T) *sshFixture {
	t.Helper()
	d, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	hash, err := auth.HashPassword("password", auth.DefaultArgon2Params())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	var aliceID int64
	for _, u := range []struct {
		name               string
		enabled, sftp, scp bool
		quota              int64
	}{
		{"alice", true, true, false, 16}, {"bob", true, true, false, 0}, {"disabled", false, true, false, 0}, {"no-ssh", true, false, false, 0}, {"scp-only", true, false, true, 0},
	} {
		userRoot := root
		if u.name != "alice" {
			userRoot = t.TempDir()
		}
		id, err := d.CreateUser(context.Background(), u.name, hash, userRoot, u.quota, u.sftp, false, false, u.scp, false)
		if err != nil {
			t.Fatal(err)
		}
		if u.name == "alice" {
			aliceID = id
		}
		if !u.enabled {
			if err := d.UpdateUser(context.Background(), id, userRoot, u.quota, false, u.sftp, false, false, u.scp, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	signer := testSigner(t)
	return &sshFixture{db: d, config: serverConfig(context.Background(), d, signer), host: signer.PublicKey(), root: root, userID: aliceID}
}

// Each connection uses a real TCP socket and the production authentication and
// channel handlers. Register cleanup after the database so handlers exit first.
func (f *sshFixture) dial(t *testing.T, user string, method ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleConn(f.db, f.config, conn, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("SSH handler did not stop")
		}
	})
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, ln.Addr().String(), &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{method}, HostKeyCallback: ssh.FixedHostKey(f.host)})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	client := ssh.NewClient(c, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client, nil
}

func (f *sshFixture) sftp(t *testing.T, user string) *sftp.Client {
	t.Helper()
	sshClient, err := f.dial(t, user, ssh.Password("password"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestSSHAuthenticationAndProtocolPermissions(t *testing.T) {
	f := newSSHFixture(t)
	for _, tc := range []struct{ user, password string }{{"unknown", "password"}, {"alice", "wrong"}, {"disabled", "password"}, {"no-ssh", "password"}} {
		t.Run(tc.user, func(t *testing.T) {
			if _, err := f.dial(t, tc.user, ssh.Password(tc.password)); err == nil {
				t.Fatal("invalid credentials or disabled access accepted")
			}
		})
	}
	t.Run("SCP-only cannot use SFTP", func(t *testing.T) {
		c, err := f.dial(t, "scp-only", ssh.Password("password"))
		if err != nil {
			t.Fatal(err)
		}
		sc, err := sftp.NewClient(c)
		if err == nil {
			sc.Close()
			t.Fatal("SCP-only user opened SFTP subsystem")
		}
	})
	t.Run("SFTP-only cannot use SCP or shell", func(t *testing.T) {
		c, err := f.dial(t, "alice", ssh.Password("password"))
		if err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"scp -t /", "sh"} {
			session, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			err = session.Start(command)
			_ = session.Close()
			if err == nil {
				t.Fatalf("unauthorized command accepted: %s", command)
			}
		}
	})
}

func TestSSHPublicKeyAuthentication(t *testing.T) {
	f := newSSHFixture(t)
	signer := testSigner(t)
	if _, err := f.db.AddSSHKey(context.Background(), f.userID, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), ssh.FingerprintSHA256(signer.PublicKey()), "test"); err != nil {
		t.Fatal(err)
	}
	c, err := f.dial(t, "alice", ssh.PublicKeys(signer))
	if err != nil {
		t.Fatalf("registered key rejected: %v", err)
	}
	client, err := sftp.NewClient(c)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.ReadDir("/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.dial(t, "alice", ssh.PublicKeys(testSigner(t))); err == nil {
		t.Fatal("unregistered key accepted")
	}
	if _, err := f.dial(t, "bob", ssh.PublicKeys(signer)); err == nil {
		t.Fatal("another user's key accepted")
	}
}

func TestSFTPFileLifecycleAndIsolation(t *testing.T) {
	f := newSSHFixture(t)
	c := f.sftp(t, "alice")
	if err := c.Mkdir("/docs"); err != nil {
		t.Fatal(err)
	}
	file, err := c.Create("/docs/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := c.ReadDir("/docs")
	if err != nil || len(entries) != 1 || entries[0].Name() != "file.txt" {
		t.Fatalf("listing: %v %v", entries, err)
	}
	if err := c.Rename("/docs/file.txt", "/docs/renamed.txt"); err != nil {
		t.Fatal(err)
	}
	file, err = c.Open("/docs/renamed.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(file)
	_ = file.Close()
	if err != nil || string(b) != "hello" {
		t.Fatalf("download: %q %v", b, err)
	}
	disk, err := os.ReadFile(filepath.Join(f.root, "docs", "renamed.txt"))
	if err != nil || string(disk) != "hello" {
		t.Fatalf("stored contents: %q %v", disk, err)
	}
	other := f.sftp(t, "bob")
	if _, err := other.Stat("/docs/renamed.txt"); err == nil {
		t.Fatal("another user can see file")
	}
	if err := c.Remove("/docs/renamed.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stat("/docs/renamed.txt"); !os.IsNotExist(err) {
		t.Fatalf("deleted file still accessible: %v", err)
	}
	if err := c.RemoveDirectory("/docs"); err != nil {
		t.Fatal(err)
	}
}

func TestSFTPQuotaIncludesExistingFiles(t *testing.T) {
	f := newSSHFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, "existing"), []byte("12345678"), 0600); err != nil {
		t.Fatal(err)
	}
	c := f.sftp(t, "alice")
	file, err := c.Create("/upload")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("12345678"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("x"), 8); err == nil {
		t.Fatal("quota overflow accepted")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(f.root, "upload"))
	if err != nil || string(b) != "12345678" {
		t.Fatalf("overflow altered stored contents: %q %v", b, err)
	}
}

func TestSFTPSymlinkEscapeRejected(t *testing.T) {
	f := newSSHFixture(t)
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.root, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	c := f.sftp(t, "alice")
	if file, err := c.Open("/escape/secret"); err == nil {
		file.Close()
		t.Fatal("read escaped jail")
	}
	if file, err := c.Create("/escape/secret"); err == nil {
		file.Close()
		t.Fatal("write escaped jail")
	}
	if err := c.Remove("/escape/secret"); err == nil {
		t.Fatal("delete escaped jail")
	}
	b, err := os.ReadFile(secret)
	if err != nil || string(b) != "private" {
		t.Fatalf("outside file altered: %q %v", b, err)
	}
}
