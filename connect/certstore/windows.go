//go:build windows

package certstore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// windowsInstaller installs the org CA into the Windows ROOT certificate store
// via `certutil -addstore -f Root <tempfile>`.
type windowsInstaller struct{}

// New returns the Windows Installer.
func New() Installer { return &windowsInstaller{} }

// Install writes the canonical CA bundle file, parses the first cert from
// the PEM, computes its SHA-1 thumbprint, and (idempotently) imports it into
// the machine ROOT store via certutil. If a cert with the same thumbprint is
// already present, this is a no-op.
func (w *windowsInstaller) Install(pemBytes []byte) (string, error) {
	if _, err := MaterializeCAFile(pemBytes); err != nil {
		return "", err
	}

	cert, err := pemFirstCert(pemBytes)
	if err != nil {
		return "", fmt.Errorf("certstore: %w", err)
	}
	thumb := sha1Hex(cert.Raw)

	if alreadyInRootStore(thumb) {
		return "Root\\" + thumb, nil
	}

	tmp, err := writeTempPEM(pemBytes)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)

	out, err := runCertutil(certutilAddArgs(tmp))
	if err != nil {
		return "", fmt.Errorf("certstore: certutil -addstore: %w (output: %s)", err, out)
	}
	return "Root\\" + thumb, nil
}

// Uninstall removes any cert from the Root store whose SHA-1 thumbprint
// matches the org CA in the canonical bundle file. If the bundle is gone,
// Uninstall is a no-op.
func (w *windowsInstaller) Uninstall() error {
	pemBytes, err := os.ReadFile(canonicalBundlePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cert, err := pemFirstCert(pemBytes)
	if err != nil {
		return fmt.Errorf("certstore: %w", err)
	}
	thumb := sha1Hex(cert.Raw)
	if !alreadyInRootStore(thumb) {
		_ = os.Remove(canonicalBundlePath())
		return nil
	}
	out, err := runCertutil(certutilDelArgs(thumb))
	if err != nil {
		return fmt.Errorf("certstore: certutil -delstore: %w (output: %s)", err, out)
	}
	_ = os.Remove(canonicalBundlePath())
	return nil
}

// canonicalBundlePath mirrors config.DefaultCAInstallPath for read paths.
func canonicalBundlePath() string {
	if d := os.Getenv("AISCANCONNECT_CA_PATH"); d != "" {
		return d
	}
	pd := os.Getenv("PROGRAMDATA")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "AIScanConnect", "aiscan.pem")
}

// runCertutil executes certutil with the given args; testable seam.
var runCertutil = func(args []string) ([]byte, error) {
	return exec.Command("certutil", args...).CombinedOutput()
}

// alreadyInRootStore returns true if `certutil -store Root <thumb>` finds a hit.
func alreadyInRootStore(thumb string) bool {
	out, err := runCertutil(certutilStoreArgs(thumb))
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(string(out)), thumb)
}

