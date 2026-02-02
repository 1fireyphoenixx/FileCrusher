package setup

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Options struct {
	DBPath  string
	DataDir string
}

func Run(ctx context.Context, opt Options) error {
	if opt.DBPath == "" {
		return errors.New("db path is required")
	}
	if opt.DataDir == "" {
		return errors.New("data-dir is required")
	}
	if err := os.MkdirAll(filepath.Dir(opt.DBPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(opt.DataDir, 0o700); err != nil {
		return err
	}

	d, err := db.Open(ctx, opt.DBPath)
	if err != nil {
		return err
	}
	defer d.Close()
	_ = os.Chmod(opt.DBPath, 0o600)

	initialized, err := d.IsInitialized(ctx)
	if err != nil {
		return err
	}
	if initialized {
		return errors.New("already initialized")
	}

	adminPass, err := promptPassword("Set initial admin password")
	if err != nil {
		return err
	}
	adminHash, err := auth.HashPassword(adminPass, auth.DefaultArgon2Params())
	if err != nil {
		return err
	}
	if err := d.SetAdminPasswordHash(ctx, adminHash); err != nil {
		return err
	}

	// Generate TLS cert/key for :5132.
	certPath := filepath.Join(opt.DataDir, "tls.crt")
	keyPath := filepath.Join(opt.DataDir, "tls.key")
	if err := ensureTLSCert(certPath, keyPath); err != nil {
		return err
	}
	if err := d.SetConfig(ctx, "tls_cert_path", certPath); err != nil {
		return err
	}
	if err := d.SetConfig(ctx, "tls_key_path", keyPath); err != nil {
		return err
	}

	// Generate SSH host key for SFTP.
	sshKeyPath := filepath.Join(opt.DataDir, "ssh_host_ed25519")
	if err := ensureSSHHostKey(sshKeyPath); err != nil {
		return err
	}
	if err := d.SetConfig(ctx, "ssh_host_key_path", sshKeyPath); err != nil {
		return err
	}

	if err := d.SetInitialized(ctx); err != nil {
		return err
	}

	return nil
}

func promptPassword(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		for {
			fmt.Fprintf(os.Stderr, "%s: ", label)
			p1b, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			fmt.Fprint(os.Stderr, "Confirm password: ")
			p2b, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			p1 := strings.TrimSpace(string(p1b))
			p2 := strings.TrimSpace(string(p2b))
			if p1 == "" {
				fmt.Fprintln(os.Stderr, "password cannot be empty")
				continue
			}
			if p1 != p2 {
				fmt.Fprintln(os.Stderr, "passwords do not match")
				continue
			}
			return p1, nil
		}
	}

	// Non-interactive fallback (e.g. piped input). Echo suppression isn't possible.
	_ = syscall.Stdin
	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprintf(os.Stderr, "%s: ", label)
		p1, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "Confirm password: ")
		p2, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		p1 = strings.TrimSpace(p1)
		p2 = strings.TrimSpace(p2)
		if p1 == "" {
			fmt.Fprintln(os.Stderr, "password cannot be empty")
			continue
		}
		if p1 != p2 {
			fmt.Fprintln(os.Stderr, "passwords do not match")
			continue
		}
		return p1, nil
	}
}

func ensureTLSCert(certPath, keyPath string) error {
	if fileExists(certPath) && fileExists(keyPath) {
		_, err := tls.LoadX509KeyPair(certPath, keyPath)
		return err
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "filecrusher",
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           nil,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		return err
	}

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return err
	}

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0o600); err != nil {
		return err
	}

	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	return err
}

func ensureSSHHostKey(path string) error {
	if fileExists(path) {
		_, err := loadSSHSigner(path)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	sshPriv, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(sshPriv), 0o600); err != nil {
		return err
	}
	_, err = loadSSHSigner(path)
	return err
}

func loadSSHSigner(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
