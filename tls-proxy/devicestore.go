// devicestore.go: writer-side append for /config/devices.json.
//
// Schema is dictated by webui's Device struct (webui/devicestore.go) and
// MUST be kept in lockstep — field names, JSON tags, and types are
// identical. The webui is the primary reader; tls-proxy only appends a
// new record per successful enrollment.
//
// Concurrency:
//   - OS-level flock on a sidecar "<DEVICES_FILE>.lock" so the webui's
//     read-modify-write paths (Revoke / UnRevoke / TouchLastSeen) are
//     serialised against tls-proxy's enrollment append.
//   - Atomic rename for the data file write, so partial writes can never
//     be observed.
//
// Failure policy:
//   - File missing -> create as `[]` (empty array).
//   - Duplicate device_id -> reject with errDeviceIDExists. The caller
//     should treat this as an internal error (we generate v4 UUIDs so a
//     real collision is astronomically unlikely; reaching this branch
//     indicates a bug or a corrupt file).
package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// device mirrors webui/devicestore.go::Device exactly. Any change here
// must be made in lockstep with the webui struct definition.
type device struct {
	DeviceID  string     `json:"device_id"`
	Subject   string     `json:"subject"`
	Org       string     `json:"org"`
	SerialHex string     `json:"serial_hex"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// errDeviceIDExists indicates a UUID collision (or corrupt file) where the
// generated device_id is already present in devices.json.
var errDeviceIDExists = errors.New("device_id already exists")

// appendDevice atomically appends d to the devices.json at path, holding a
// flock on lockPath for the duration of the read-modify-write. lockTimeout
// bounds how long we will wait for the lock; on timeout the call returns
// ErrFlockTimeout (handled by the HTTP layer as 503).
func appendDevice(path, lockPath string, lockTimeout time.Duration, d device) error {
	return WithFlock(lockPath, lockTimeout, func() error {
		existing, err := readDevicesFile(path)
		if err != nil {
			return fmt.Errorf("read devices: %w", err)
		}
		for _, e := range existing {
			if e.DeviceID == d.DeviceID {
				return errDeviceIDExists
			}
		}
		existing = append(existing, d)
		return writeDevicesFile(path, existing)
	})
}

func readDevicesFile(path string) ([]device, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var devs []device
	if err := json.Unmarshal(data, &devs); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return devs, nil
}

func writeDevicesFile(path string, devs []device) error {
	if devs == nil {
		devs = []device{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(devs, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// newDeviceID returns a random v4-shaped UUID string. We don't depend on
// any UUID library to keep the dependency surface minimal; the format is
// xxxxxxxx-xxxx-4xxx-Nxxx-xxxxxxxxxxxx where N is one of 8/9/a/b.
func newDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Set version (4) and variant (RFC 4122).
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
