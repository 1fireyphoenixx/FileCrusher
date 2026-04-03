package install

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"filecrusher/internal/cmd/setup"
)

type Options struct {
	DataDir          string
	BinDir           string
	DBPath           string
	AdminPassword    string
	AdminPasswordEnv bool
	RegenTLS         bool
	Yes              bool
}

func Run(args []string) error {
	defaults := defaultsForOS(runtime.GOOS)

	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var opt Options
	fs.StringVar(&opt.DataDir, "data-dir", "", "data directory (db/keys/certs)")
	fs.StringVar(&opt.BinDir, "bin-dir", "", "directory to install filecrusher binary")
	fs.StringVar(&opt.DBPath, "db", "", "sqlite database path (defaults to <data-dir>/filecrusher.db)")
	fs.StringVar(&opt.AdminPassword, "admin-password", "", "set initial admin password non-interactively")
	fs.BoolVar(&opt.AdminPasswordEnv, "admin-password-env", false, "read initial admin password from FILECRUSHER_ADMIN_PASSWORD")
	fs.BoolVar(&opt.RegenTLS, "regen-tls", false, "overwrite tls.crt/tls.key in data-dir")
	fs.BoolVar(&opt.Yes, "yes", false, "accept defaults for any missing values")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var err error
	if opt.DataDir == "" {
		if opt.Yes {
			opt.DataDir = defaults.dataDir
		} else {
			opt.DataDir, err = promptPath("Data directory", defaults.dataDir)
			if err != nil {
				return err
			}
		}
	}

	if opt.BinDir == "" {
		if opt.Yes {
			opt.BinDir = defaults.binDir
		} else {
			opt.BinDir, err = promptPath("Binary install directory", defaults.binDir)
			if err != nil {
				return err
			}
		}
	}

	opt.DataDir, err = normalizePath(opt.DataDir)
	if err != nil {
		return err
	}
	opt.BinDir, err = normalizePath(opt.BinDir)
	if err != nil {
		return err
	}

	if opt.DBPath == "" {
		opt.DBPath = filepath.Join(opt.DataDir, "filecrusher.db")
	}
	opt.DBPath, err = normalizePath(opt.DBPath)
	if err != nil {
		return err
	}

	dstBinary := filepath.Join(opt.BinDir, binaryName(runtime.GOOS))
	if err := installBinary(dstBinary); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Installed binary: %s\n", dstBinary)

	setupArgs := []string{"--db", opt.DBPath, "--data-dir", opt.DataDir}
	if opt.AdminPassword != "" {
		setupArgs = append(setupArgs, "--admin-password", opt.AdminPassword)
	}
	if opt.AdminPasswordEnv {
		setupArgs = append(setupArgs, "--admin-password-env")
	}
	if opt.RegenTLS {
		setupArgs = append(setupArgs, "--regen-tls")
	}

	fmt.Fprintf(os.Stderr, "Initializing database: %s\n", opt.DBPath)
	if err := setup.Run(setupArgs); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Install complete.")
	return nil
}

type installerDefaults struct {
	dataDir string
	binDir  string
}

func defaultsForOS(goos string) installerDefaults {
	home, _ := os.UserHomeDir()
	dataDir := "./data"
	binDir := filepath.Join(home, ".local", "bin")
	if home == "" {
		binDir = "."
	}

	if goos == "windows" {
		if home == "" {
			binDir = "."
		} else {
			binDir = filepath.Join(home, "AppData", "Local", "Programs", "FileCrusher")
		}
	}

	return installerDefaults{dataDir: dataDir, binDir: binDir}
}

func promptPath(label, def string) (string, error) {
	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, def)
		v, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		v = strings.TrimSpace(v)
		if v == "" {
			v = def
		}
		if v == "" {
			fmt.Fprintln(os.Stderr, "path cannot be empty")
			if errors.Is(err, io.EOF) {
				return "", errors.New("path cannot be empty")
			}
			continue
		}
		return v, nil
	}
}

func normalizePath(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", errors.New("path cannot be empty")
	}
	if v == "~" || strings.HasPrefix(v, "~/") || strings.HasPrefix(v, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", errors.New("failed to resolve home directory")
		}
		if v == "~" {
			v = home
		} else {
			v = filepath.Join(home, v[2:])
		}
	}
	return filepath.Clean(v), nil
}

func binaryName(goos string) string {
	if goos == "windows" {
		return "filecrusher.exe"
	}
	return "filecrusher"
}

func installBinary(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	src, err = filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}

	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	if srcAbs == dstAbs {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dstAbs), 0o755); err != nil {
		return err
	}

	in, err := os.Open(srcAbs)
	if err != nil {
		return err
	}
	defer in.Close()

	mode := os.FileMode(0o755)
	if st, statErr := in.Stat(); statErr == nil {
		if perm := st.Mode().Perm(); perm != 0 {
			mode = perm
		}
	}

	tmp := dstAbs + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	_ = os.Remove(dstAbs)
	if err := os.Rename(tmp, dstAbs); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
