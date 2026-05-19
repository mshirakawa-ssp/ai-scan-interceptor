// Package certstore installs the organization CA certificate into the OS
// trust store and into a stable path for env-var-based consumers
// (NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, ...).
//
// OS specifics live in linux.go / darwin.go / windows.go behind build tags.
package certstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"ai-scan-connect/config"
)

// ErrNotImplemented is returned by stub OS backends.
var ErrNotImplemented = errors.New("certstore: not implemented on this platform")

// Installer installs/uninstalls a CA cert in the OS trust store.
type Installer interface {
	// Install writes pem to the OS trust store and returns the canonical path
	// where the file was placed.
	Install(pem []byte) (path string, err error)

	// Uninstall removes any artifacts previously placed by Install.
	Uninstall() error
}

// MaterializeCAFile writes the PEM to DefaultCAInstallPath with 0644 perms.
// This is the common helper used by all OS backends and by env-var consumers
// (NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE).
func MaterializeCAFile(pem []byte) (string, error) {
	dst := config.DefaultCAInstallPath()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", fmt.Errorf("certstore: mkdir %s: %w", filepath.Dir(dst), err)
	}
	if err := os.WriteFile(dst, pem, 0o644); err != nil {
		return "", fmt.Errorf("certstore: write %s: %w", dst, err)
	}
	return dst, nil
}
