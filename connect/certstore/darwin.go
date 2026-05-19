//go:build darwin

package certstore

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// darwinInstaller installs the org CA into the macOS System keychain via the
// `security` CLI. Requires root (sudo) at install time; fails clearly otherwise.
type darwinInstaller struct{}

// New returns the macOS Installer.
func New() Installer { return &darwinInstaller{} }

// Install writes the canonical CA bundle file and adds the cert as a trusted
// root in the System keychain. Idempotent: if a cert with the same SHA-1
// thumbprint is already present (matched by Common Name), this is a no-op.
func (d *darwinInstaller) Install(pemBytes []byte) (string, error) {
	if _, err := MaterializeCAFile(pemBytes); err != nil {
		return "", err
	}
	cert, err := pemFirstCert(pemBytes)
	if err != nil {
		return "", fmt.Errorf("certstore: %w", err)
	}
	thumb := sha1Hex(cert.Raw)

	if alreadyInSystemKeychain(cert.Subject.CommonName, thumb) {
		return SystemKeychain + ":" + thumb, nil
	}

	tmp, err := writeTempPEM(pemBytes)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)

	out, err := runSecurity(securityAddTrustedArgs(SystemKeychain, tmp))
	if err != nil {
		return "", fmt.Errorf("certstore: security add-trusted-cert: %w (output: %s)", err, out)
	}
	return SystemKeychain + ":" + thumb, nil
}

// Uninstall removes any cert from the System keychain matching the CN of the
// org CA in the canonical bundle. If the bundle is gone, Uninstall is a no-op.
func (d *darwinInstaller) Uninstall() error {
	pemBytes, err := os.ReadFile(canonicalBundlePathDarwin())
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
	cn := cert.Subject.CommonName
	if cn == "" {
		return fmt.Errorf("certstore: cert has empty CN, cannot delete by name")
	}
	out, err := runSecurity(securityDeleteByCNArgs(SystemKeychain, cn))
	if err != nil {
		// "could not be found" is fine — already removed.
		if strings.Contains(strings.ToLower(string(out)), "could not be found") {
			_ = os.Remove(canonicalBundlePathDarwin())
			return nil
		}
		return fmt.Errorf("certstore: security delete-certificate: %w (output: %s)", err, out)
	}
	_ = os.Remove(canonicalBundlePathDarwin())
	return nil
}

// canonicalBundlePathDarwin returns the canonical CA bundle path for macOS.
// We honor AISCANCONNECT_CA_PATH for dev/CI and otherwise default to
// /etc/ssl/certs/aiscan.pem (the same path used elsewhere on Unix).
func canonicalBundlePathDarwin() string {
	if d := os.Getenv("AISCANCONNECT_CA_PATH"); d != "" {
		return d
	}
	return "/etc/ssl/certs/aiscan.pem"
}

// runSecurity executes the `security` CLI with the given args; testable seam.
var runSecurity = func(args []string) ([]byte, error) {
	return exec.Command("security", args...).CombinedOutput()
}

// alreadyInSystemKeychain checks whether a cert with the given CN AND thumb
// already exists in the System keychain. We match on both to avoid removing
// an unrelated cert with a colliding CN.
func alreadyInSystemKeychain(cn, thumb string) bool {
	if cn == "" {
		return false
	}
	out, err := runSecurity(securityFindByCNArgs(SystemKeychain, cn))
	if err != nil {
		return false
	}
	// `security find-certificate -Z` prints lines like:
	//   SHA-1 hash: ABCD...EF
	// We compare without separators, uppercase.
	upper := strings.ToUpper(string(out))
	return strings.Contains(upper, thumb)
}
