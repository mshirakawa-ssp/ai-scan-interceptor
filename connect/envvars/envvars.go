// Package envvars manages OS-level environment variable injection for
// proxy + extra-CA settings, idempotently, via a managed marker block.
package envvars

import "errors"

// ErrNotImplemented indicates a Phase 2 stub.
var ErrNotImplemented = errors.New("envvars: not implemented on this platform")

// Vars is the set of variables ai-scan-connect manages.
type Vars struct {
	HTTPSProxy        string // e.g. "http://127.0.0.1:8443"
	HTTPProxy         string // e.g. "http://127.0.0.1:8443"
	NodeExtraCACerts  string // path to org CA PEM
	RequestsCABundle  string // path to org CA PEM (Python `requests`)
	SSLCertFile       string // path to org CA PEM (curl, OpenSSL)
}

// Manager applies / removes the managed env var block.
type Manager interface {
	// Apply writes the managed block (idempotently) into all relevant rc files
	// (or registry on Windows). Returns the list of paths touched.
	Apply(v Vars) (touched []string, err error)

	// Remove strips the managed block from all relevant locations.
	Remove() (touched []string, err error)

	// CheckIntegrity returns the list of locations whose managed block is
	// missing or stale relative to v.
	CheckIntegrity(v Vars) (drift []string, err error)
}

// New returns the OS-specific Manager.
//
// (Implementation lives in unix.go / windows.go behind build tags.)
func New() Manager { return newManager() }
