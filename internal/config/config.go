// Package config loads and validates FileCrusher YAML configuration.
// It applies defaults so the daemon can rely on fully populated values.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// TLSConfig holds TLS certificate paths.
type TLSConfig struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level string `yaml:"level"`
}

// DBConfig holds database settings.
type DBConfig struct {
	Path string `yaml:"path"`
}

// HTTPConfig holds HTTP server settings.
type HTTPConfig struct {
	Bind        string    `yaml:"bind"`
	Port        int       `yaml:"port"`
	MaxUploadMB int       `yaml:"max_upload_mb"`
	TLS         TLSConfig `yaml:"tls"`
}

// SSHConfig holds SSH server settings.
type SSHConfig struct {
	Bind        string `yaml:"bind"`
	Port        int    `yaml:"port"`
	HostKeyPath string `yaml:"host_key_path"`
}

// FTPConfig holds FTP server settings.
type FTPConfig struct {
	Enable       bool   `yaml:"enable"`
	ExplicitTLS  bool   `yaml:"explicit_tls"`
	Port         int    `yaml:"port"`
	PassivePorts string `yaml:"passive_ports"`
	PublicHost   string `yaml:"public_host"`
}

// FTPSConfig holds FTPS server settings.
type FTPSConfig struct {
	Enable       bool   `yaml:"enable"`
	Port         int    `yaml:"port"`
	PassivePorts string `yaml:"passive_ports"`
	PublicHost   string `yaml:"public_host"`
}

// WebDAVConfig holds WebDAV settings.
type WebDAVConfig struct {
	Enable bool   `yaml:"enable"`
	Prefix string `yaml:"prefix"`
}

// Config mirrors the filecrusher.yaml schema.
type Config struct {
	Log          LogConfig    `yaml:"log"`
	DB           DBConfig     `yaml:"db"`
	DataDir      string       `yaml:"data_dir"`
	HTTP         HTTPConfig   `yaml:"http"`
	SSH          SSHConfig    `yaml:"ssh"`
	FTP          FTPConfig    `yaml:"ftp"`
	FTPS         FTPSConfig   `yaml:"ftps"`
	FTPSImplicit FTPSConfig   `yaml:"ftps_implicit"`
	WebDAV       WebDAVConfig `yaml:"webdav"`
}

// Load reads a YAML config file, applies defaults, and validates it.
// It returns a fully populated Config or a descriptive error.
func Load(path string) (Config, error) {
	var c Config
	if path == "" {
		return c, errors.New("config path is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, err
	}
	applyDefaults(&c)
	if err := validate(&c); err != nil {
		return Config{}, err
	}
	// Make paths stable for daemon.
	c.DB.Path = strings.TrimSpace(c.DB.Path)
	c.DataDir = strings.TrimSpace(c.DataDir)
	c.HTTP.TLS.CertPath = strings.TrimSpace(c.HTTP.TLS.CertPath)
	c.HTTP.TLS.KeyPath = strings.TrimSpace(c.HTTP.TLS.KeyPath)
	c.SSH.HostKeyPath = strings.TrimSpace(c.SSH.HostKeyPath)
	return c, nil
}

// applyDefaults populates zero-values with sane defaults.
// Defaults match the values described in README and example config.
func applyDefaults(c *Config) {
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.DB.Path == "" {
		c.DB.Path = "./data/filecrusher.db"
	}
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.HTTP.Bind == "" {
		c.HTTP.Bind = "127.0.0.1"
	}
	if c.HTTP.Port == 0 {
		c.HTTP.Port = 5132
	}
	if c.HTTP.MaxUploadMB == 0 {
		c.HTTP.MaxUploadMB = 512
	}
	if c.SSH.Bind == "" {
		c.SSH.Bind = c.HTTP.Bind
	}
	if c.SSH.Port == 0 {
		c.SSH.Port = 2022
	}
	if c.FTP.Port == 0 {
		c.FTP.Port = 2121
	}
	// By default, keep explicit TLS on the FTP listener disabled.
	// This preserves legacy behavior; enable it explicitly if you want AUTH TLS on ftp.port.
	if c.FTP.PassivePorts == "" {
		c.FTP.PassivePorts = "50000-50100"
	}
	if c.FTPS.Port == 0 {
		c.FTPS.Port = 2122
	}
	if c.FTPS.PassivePorts == "" {
		c.FTPS.PassivePorts = c.FTP.PassivePorts
	}
	if c.FTPSImplicit.Port == 0 {
		c.FTPSImplicit.Port = 990
	}
	if c.FTPSImplicit.PassivePorts == "" {
		c.FTPSImplicit.PassivePorts = c.FTP.PassivePorts
	}
	if c.WebDAV.Prefix == "" {
		c.WebDAV.Prefix = "/webdav"
	}
}

// validate performs basic sanity checks for required fields and ranges.
// It does not mutate the config.
func validate(c *Config) error {
	if strings.TrimSpace(c.Log.Level) == "" {
		return errors.New("log.level is required")
	}
	if c.DB.Path == "" {
		return errors.New("db.path is required")
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if c.HTTP.Port <= 0 || c.HTTP.Port > 65535 {
		return errors.New("http.port is invalid")
	}
	if c.HTTP.MaxUploadMB < 1 || c.HTTP.MaxUploadMB > 102400 {
		return errors.New("http.max_upload_mb is invalid")
	}
	if c.SSH.Port <= 0 || c.SSH.Port > 65535 {
		return errors.New("ssh.port is invalid")
	}
	if c.FTP.Port <= 0 || c.FTP.Port > 65535 {
		return errors.New("ftp.port is invalid")
	}
	if c.FTPS.Port <= 0 || c.FTPS.Port > 65535 {
		return errors.New("ftps.port is invalid")
	}
	if c.FTPSImplicit.Port <= 0 || c.FTPSImplicit.Port > 65535 {
		return errors.New("ftps_implicit.port is invalid")
	}
	if c.FTP.ExplicitTLS || c.FTPS.Enable || c.FTPSImplicit.Enable {
		// If either TLS path is set, require both.
		cp := strings.TrimSpace(c.HTTP.TLS.CertPath)
		kp := strings.TrimSpace(c.HTTP.TLS.KeyPath)
		if (cp == "") != (kp == "") {
			return errors.New("http.tls.cert_path and http.tls.key_path must be set together")
		}
	}
	// Basic sanity for paths.
	_ = filepath.Clean(c.DB.Path)
	_ = filepath.Clean(c.DataDir)
	if c.HTTP.TLS.CertPath != "" {
		_ = filepath.Clean(c.HTTP.TLS.CertPath)
		_ = filepath.Clean(c.HTTP.TLS.KeyPath)
	}
	if c.SSH.HostKeyPath != "" {
		_ = filepath.Clean(c.SSH.HostKeyPath)
	}
	return nil
}
