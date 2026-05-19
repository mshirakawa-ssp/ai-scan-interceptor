//go:build windows

package certstore

import (
	"fmt"
	"os/exec"
	"strings"
)

// EnumerateDistros runs `wsl.exe -l -q` and returns the filtered list of
// installed distros (UTF-16LE output is decoded). Docker Desktop's backing
// distros are excluded.
func EnumerateDistros() ([]string, error) {
	out, err := runWSL([]string{"-l", "-q"})
	if err != nil {
		return nil, fmt.Errorf("wsl: enumerate: %w (output: %q)", err, string(out))
	}
	return parseWslList(out)
}

// InstallInDistro installs the org CA and proxy/env config inside one WSL
// distro. listenAddr is the local listen address to which Connect on the
// Windows host has bound (e.g. "127.0.0.1:8443"); inside WSL2 this resolves
// to the Windows host via the standard WSL2 nameserver bridge for 127.0.0.1
// access — operators may need to use the host gateway IP for WSL2; that's a
// Phase 2 concern. For WSL1, 127.0.0.1 is the same host.
//
// markerStart/markerEnd should match envvars.MarkerStart / MarkerEnd so that
// `monitor` and `uninstall` can later detect/strip the same blocks.
func InstallInDistro(distro string, pemBytes []byte, listenAddr, markerStart, markerEnd string) error {
	if distro == "" {
		return fmt.Errorf("wsl: empty distro name")
	}

	// Stage the CA inside the distro's filesystem at a stable path. We use
	// /tmp inside WSL via `\\wsl$\<distro>\tmp` would need NTFS permissions;
	// instead we pipe the PEM through stdin and write it within the script.
	// Simpler approach: drop the PEM via `wsl -d <distro> -u root tee`.
	stageCmd := exec.Command("wsl.exe", "-d", distro, "-u", "root", "--",
		"/bin/sh", "-c", "umask 022; cat > /tmp/aiscan-ca.pem")
	stageCmd.Stdin = strings.NewReader(string(pemBytes))
	if out, err := stageCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wsl[%s]: stage CA: %w (output: %s)", distro, err, out)
	}

	// Now run the install script with AISCAN_CA_PATH set to the staged file.
	script := BuildWSLInstallScript(listenAddr, markerStart, markerEnd)
	cmd := exec.Command("wsl.exe", "-d", distro, "-u", "root", "--",
		"/bin/sh", "-c", "AISCAN_CA_PATH=/tmp/aiscan-ca.pem /bin/sh -s")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	// Always try to clean up the staged PEM, regardless of success.
	cleanup := exec.Command("wsl.exe", "-d", distro, "-u", "root", "--",
		"/bin/sh", "-c", "rm -f /tmp/aiscan-ca.pem")
	_, _ = cleanup.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wsl[%s]: install script: %w (output: %s)", distro, err, out)
	}
	return nil
}

// runWSL is a testable seam around `wsl.exe`.
var runWSL = func(args []string) ([]byte, error) {
	return exec.Command("wsl.exe", args...).CombinedOutput()
}

// (Keep ListWSLDistros as an alias for backward compatibility with any
// earlier callers that referenced the Phase 1 stub name.)

// ListWSLDistros is a deprecated alias for EnumerateDistros.
//
// Deprecated: use EnumerateDistros.
func ListWSLDistros() ([]string, error) { return EnumerateDistros() }

// InstallInWSL is a deprecated alias for InstallInDistro using empty markers.
//
// Deprecated: use InstallInDistro with explicit markers.
func InstallInWSL(distro string, pemBytes []byte) error {
	return InstallInDistro(distro, pemBytes, "127.0.0.1:8443",
		"# >>> ai-scan-connect managed block (DO NOT EDIT) v1 >>>",
		"# <<< ai-scan-connect managed block <<<")
}

