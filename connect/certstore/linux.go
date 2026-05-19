//go:build linux

package certstore

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// linuxInstaller installs a CA into the system anchor directory and runs
// update-ca-certificates / update-ca-trust as appropriate.
type linuxInstaller struct{}

// New returns the Linux Installer.
func New() Installer { return &linuxInstaller{} }

// candidate anchor dirs for major distros. First existing wins.
var linuxAnchorDirs = []string{
	"/usr/local/share/ca-certificates", // Debian/Ubuntu (.crt expected)
	"/etc/pki/ca-trust/source/anchors", // RHEL/Fedora/CentOS
	"/etc/ca-certificates/trust-source/anchors", // Arch
}

const linuxAnchorBaseName = "ai-scan-connect-org-ca"

func (l *linuxInstaller) Install(pem []byte) (string, error) {
	// Always materialize the canonical bundle file (for NODE_EXTRA_CA_CERTS).
	if _, err := MaterializeCAFile(pem); err != nil {
		return "", err
	}

	// Try to install into system anchor dir if running as root.
	dir := pickAnchorDir()
	if dir == "" {
		// No system-wide trust store reachable: still succeed (env-var-only mode).
		return "", nil
	}

	// File extension matters on Debian/Ubuntu (must be .crt).
	ext := ".pem"
	if dir == "/usr/local/share/ca-certificates" {
		ext = ".crt"
	}
	dst := filepath.Join(dir, linuxAnchorBaseName+ext)

	if err := os.WriteFile(dst, pem, 0o644); err != nil {
		return "", fmt.Errorf("certstore: write %s: %w (need root?)", dst, err)
	}

	if err := refreshLinuxTrust(); err != nil {
		// Roll back the file so we don't leave a half-applied state.
		_ = os.Remove(dst)
		return "", err
	}
	return dst, nil
}

func (l *linuxInstaller) Uninstall() error {
	var errs []error
	for _, d := range linuxAnchorDirs {
		for _, ext := range []string{".pem", ".crt"} {
			p := filepath.Join(d, linuxAnchorBaseName+ext)
			if _, err := os.Stat(p); err == nil {
				if err := os.Remove(p); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if err := refreshLinuxTrust(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func pickAnchorDir() string {
	for _, d := range linuxAnchorDirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	return ""
}

func refreshLinuxTrust() error {
	// Try update-ca-certificates first (Debian/Ubuntu), then update-ca-trust (RHEL).
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		out, err := exec.Command("update-ca-certificates").CombinedOutput()
		if err != nil {
			return fmt.Errorf("update-ca-certificates: %w (output: %s)", err, string(out))
		}
		return nil
	}
	if _, err := exec.LookPath("update-ca-trust"); err == nil {
		out, err := exec.Command("update-ca-trust", "extract").CombinedOutput()
		if err != nil {
			return fmt.Errorf("update-ca-trust: %w (output: %s)", err, string(out))
		}
		return nil
	}
	// No refresher found; not fatal — the file is in place.
	return nil
}
