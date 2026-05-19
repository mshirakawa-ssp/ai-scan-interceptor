// Package config loads and locates the connect agent configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config is the on-disk configuration for ai-scan-connect.
//
// Loaded from /etc/ai-scan-connect/config.json on Unix and
// %PROGRAMDATA%\AIScanConnect\config.json on Windows.
type Config struct {
	// InterceptorURL is the base URL of the customer interceptor (mTLS proxy).
	// e.g. "https://acme.cloud.secscanpro.com"
	InterceptorURL string `json:"interceptor_url"`

	// EnrollURL is the URL of the /enroll endpoint that signs CSRs.
	// e.g. "https://acme.cloud.secscanpro.com:3131/enroll"
	EnrollURL string `json:"enroll_url"`

	// OrgCAPEM is the PEM-encoded organization CA certificate.
	// Used both for trust store install and as the trust anchor for mTLS.
	OrgCAPEM string `json:"org_ca_pem"`

	// EnrollmentToken is a one-time token issued by the WebUI; consumed on first enroll.
	EnrollmentToken string `json:"enrollment_token"`

	// LocalListen is the listen address for the local forwarding proxy.
	// Defaults to 127.0.0.1:8443 if empty.
	LocalListen string `json:"local_listen"`

	// FailClose: when true, refuse traffic if mTLS / interceptor unavailable.
	// When false, fall back to direct connection.
	FailClose bool `json:"fail_close"`

	// Org is the organization slug (used as O= in CSR subject). Optional.
	Org string `json:"org"`
}

// DefaultConfigPath returns the OS-standard absolute path to the config file.
func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "AIScanConnect", "config.json")
	}
	return "/etc/ai-scan-connect/config.json"
}

// DefaultStateDir returns the OS-standard absolute path for runtime state
// (keys, certs, cached data).
//
// AISCANCONNECT_STATE_DIR overrides this — useful for dev/CI where the
// process can't write under /var/lib.
func DefaultStateDir() string {
	if v := os.Getenv("AISCANCONNECT_STATE_DIR"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "AIScanConnect")
	}
	return "/var/lib/ai-scan-connect"
}

// DefaultCAInstallPath returns where the org CA PEM is materialized
// for NODE_EXTRA_CA_CERTS-style consumers (Unix only meaningful path).
//
// AISCANCONNECT_CA_PATH overrides this for dev/CI.
func DefaultCAInstallPath() string {
	if v := os.Getenv("AISCANCONNECT_CA_PATH"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(DefaultStateDir(), "aiscan.pem")
	}
	return "/etc/ssl/certs/aiscan.pem"
}

// DefaultLogPath returns the standard log file location.
func DefaultLogPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(DefaultStateDir(), "ai-scan-connect.log")
	}
	return "/var/log/ai-scan-connect.log"
}

// Load reads the config at path (or DefaultConfigPath if empty).
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.applyDefaults(); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() error {
	if c.LocalListen == "" {
		c.LocalListen = "127.0.0.1:8443"
	}
	return nil
}

func (c *Config) validate() error {
	if c.InterceptorURL == "" {
		return errors.New("config: interceptor_url is required")
	}
	if c.EnrollURL == "" {
		return errors.New("config: enroll_url is required")
	}
	if c.OrgCAPEM == "" {
		return errors.New("config: org_ca_pem is required")
	}
	return nil
}

// Save persists the config back to disk (used by `install` to seed defaults
// when bootstrapping). Path empty -> DefaultConfigPath.
func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
