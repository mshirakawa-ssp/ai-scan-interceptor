package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Device represents a single endpoint (Connect agent) that has enrolled with
// the Interceptor. Records are written by the tls-proxy /enroll endpoint when
// it issues a client certificate; revocation is done from the WebUI.
//
// The WebUI primarily reads this file; tls-proxy is the writer for new
// enrollments. We tolerate concurrent writes from tls-proxy by re-reading
// the file under lock for every mutation.
//
// SerialHex is the lowercase, separator-free hex of the issued certificate's
// serial number. tls-proxy MUST populate this on enrollment so the WebUI can
// push the same serial into /config/revoked-serials.json on Revoke. The CRL
// is the only source-of-truth tls-proxy consults to enforce revocation; the
// `Revoked` flag here is purely for UI display / audit.
type Device struct {
	DeviceID  string     `json:"device_id"`
	Subject   string     `json:"subject"`     // certificate subject (e.g. "alice@WIN-042")
	Org       string     `json:"org"`         // organization name (CN's O field)
	SerialHex string     `json:"serial_hex"`  // cert serial, lowercase hex; tls-proxy writes this on enroll
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// DeviceStore is a thread-safe, file-backed list of enrolled devices.
//
// On Revoke / UnRevoke, the store also updates a paired CRLStore so
// tls-proxy (which polls /config/revoked-serials.json every 30s) sees the
// change without an extra round-trip. The CRL is optional — tests can
// construct a DeviceStore without one — but production callers should
// always wire it via SetCRL.
type DeviceStore struct {
	mu      sync.RWMutex
	path    string
	devices []*Device
	crl     *CRLStore // optional; nil-safe in all methods
}

func newDeviceStore(path string) (*DeviceStore, error) {
	s := &DeviceStore{path: path}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load devices: %w", err)
	}
	return s, nil
}

// SetCRL wires the revocation list this DeviceStore should keep in sync with.
// Safe to call once at startup; not safe to swap concurrently with Revoke.
func (s *DeviceStore) SetCRL(crl *CRLStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crl = crl
}

func (s *DeviceStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var devices []*Device
	if err := json.Unmarshal(data, &devices); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = devices
	return nil
}

// reloadUnlocked re-reads the file from disk before a mutation, so writes from
// tls-proxy are not lost. Caller must hold s.mu.
func (s *DeviceStore) reloadUnlocked() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.devices = nil
			return nil
		}
		return err
	}
	if len(data) == 0 {
		s.devices = nil
		return nil
	}
	var devices []*Device
	if err := json.Unmarshal(data, &devices); err != nil {
		return fmt.Errorf("reload parse: %w", err)
	}
	s.devices = devices
	return nil
}

func (s *DeviceStore) saveUnlocked() error {
	if s.devices == nil {
		s.devices = []*Device{}
	}
	data, err := json.MarshalIndent(s.devices, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.path, data, 0600)
}

// List returns a copy of all devices, in insertion order.
func (s *DeviceStore) List() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, *d)
	}
	return out
}

// GetByID returns a copy of the device with the given ID.
func (s *DeviceStore) GetByID(id string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.devices {
		if d.DeviceID == id {
			return *d, true
		}
	}
	return Device{}, false
}

// Add appends a new device and persists. Used by tests and by future internal
// flows; in production tls-proxy writes the file directly.
func (s *DeviceStore) Add(d Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadUnlocked(); err != nil {
		return err
	}
	for _, existing := range s.devices {
		if existing.DeviceID == d.DeviceID {
			return errors.New("device_id already exists")
		}
	}
	dc := d
	s.devices = append(s.devices, &dc)
	return s.saveUnlocked()
}

// Revoke marks the device as revoked AND inserts the cert serial into the CRL
// (if one is wired). Returns ErrDeviceNotFound if the device is absent.
//
// Idempotent: re-revoking a revoked device is a no-op (still re-inserts into
// the CRL on the off chance the CRL was wiped while the device record was
// retained — CRL.Add is itself idempotent so this is safe).
func (s *DeviceStore) Revoke(id string) error {
	s.mu.Lock()
	if err := s.reloadUnlocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	var found *Device
	for _, d := range s.devices {
		if d.DeviceID == id {
			found = d
			break
		}
	}
	if found == nil {
		s.mu.Unlock()
		return ErrDeviceNotFound
	}
	if !found.Revoked {
		now := time.Now().UTC()
		found.Revoked = true
		found.RevokedAt = &now
		if err := s.saveUnlocked(); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	// Snapshot what we need before releasing the lock — CRL.Add takes its own
	// lock, so we drop ours first to avoid a lock-order inversion if anyone
	// later wires the CRL to call back into the device store.
	serial := found.SerialHex
	subject := found.Subject
	crl := s.crl
	s.mu.Unlock()

	if crl != nil && serial != "" {
		if err := crl.Add(serial, subject); err != nil {
			return fmt.Errorf("device revoked but CRL update failed: %w", err)
		}
	}
	return nil
}

// UnRevoke clears the revoked flag on the device record AND removes the cert
// serial from the CRL. Use only for administrative correction (issued cert
// will become accepted again as long as it has not also expired).
func (s *DeviceStore) UnRevoke(id string) error {
	s.mu.Lock()
	if err := s.reloadUnlocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	var found *Device
	for _, d := range s.devices {
		if d.DeviceID == id {
			found = d
			break
		}
	}
	if found == nil {
		s.mu.Unlock()
		return ErrDeviceNotFound
	}
	if found.Revoked {
		found.Revoked = false
		found.RevokedAt = nil
		if err := s.saveUnlocked(); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	serial := found.SerialHex
	crl := s.crl
	s.mu.Unlock()

	if crl != nil && serial != "" {
		if err := crl.Remove(serial); err != nil {
			return fmt.Errorf("device unrevoked but CRL update failed: %w", err)
		}
	}
	return nil
}

// TouchLastSeen updates the LastSeen timestamp for a device.
func (s *DeviceStore) TouchLastSeen(id string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadUnlocked(); err != nil {
		return err
	}
	for _, d := range s.devices {
		if d.DeviceID == id {
			tt := t.UTC()
			d.LastSeen = &tt
			return s.saveUnlocked()
		}
	}
	return ErrDeviceNotFound
}

// ErrDeviceNotFound is returned when a lookup or mutation targets an unknown ID.
var ErrDeviceNotFound = errors.New("device not found")
