package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// crlSchemaVersion is the on-disk version stored at /config/revoked-serials.json.
// Bump this on incompatible schema changes; tls-proxy reads the same field.
const crlSchemaVersion = 1

// RevokedEntry is one row in /config/revoked-serials.json. The schema MUST
// stay byte-compatible with tls-proxy/crl reader — see PLAN_CONNECT_MTLS.md.
//
// serial_hex: lowercase hex of the cert serial number, no separators, no "0x"
//             prefix. Leading zeros are preserved if the consumer wrote them;
//             we normalize on Add to match what tls-proxy emits.
type RevokedEntry struct {
	SerialHex string    `json:"serial_hex"`
	Subject   string    `json:"subject,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
}

// crlFile is the on-disk format of revoked-serials.json.
type crlFile struct {
	Version int            `json:"version"`
	Revoked []RevokedEntry `json:"revoked"`
}

// CRLStore is a thread-safe, file-backed list of revoked client-certificate
// serials. tls-proxy polls the same file every 30s; both sides MUST keep the
// schema in lockstep with PLAN_CONNECT_MTLS.md / docs/.
//
// Writes use the existing atomicWrite helper (temp+rename, 0600) so a reader
// never observes a partial file.
type CRLStore struct {
	mu      sync.RWMutex
	path    string
	entries []RevokedEntry
}

// newCRLStore loads /config/revoked-serials.json or starts with an empty list.
// Missing file is NOT an error — that just means nothing is revoked yet.
func newCRLStore(path string) (*CRLStore, error) {
	s := &CRLStore{path: path}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load CRL: %w", err)
	}
	return s, nil
}

func (s *CRLStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var cf crlFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return fmt.Errorf("parse CRL: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = cf.Revoked
	return nil
}

// saveUnlocked persists the current list. Caller must hold s.mu.
func (s *CRLStore) saveUnlocked() error {
	if s.entries == nil {
		s.entries = []RevokedEntry{}
	}
	cf := crlFile{Version: crlSchemaVersion, Revoked: s.entries}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.path, data, 0600)
}

// normalizeSerial returns the lowercase, separator-free hex representation
// that we agreed on with tls-proxy. Empty input maps to empty output (caller
// rejects empty serials separately).
func normalizeSerial(s string) string {
	out := strings.ToLower(strings.TrimSpace(s))
	out = strings.TrimPrefix(out, "0x")
	out = strings.ReplaceAll(out, ":", "")
	out = strings.ReplaceAll(out, " ", "")
	return out
}

// Add appends an entry for the given serial. If the serial is already in the
// CRL, this is a no-op (preserves the original revoked_at — first revocation
// timestamp wins, which matches "first wins" semantics for audit).
//
// Returns nil if added or already present; error only on validation/IO.
func (s *CRLStore) Add(serial, subject string) error {
	serial = normalizeSerial(serial)
	if serial == "" {
		return fmt.Errorf("serial must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.SerialHex == serial {
			return nil // already revoked
		}
	}
	s.entries = append(s.entries, RevokedEntry{
		SerialHex: serial,
		Subject:   subject,
		RevokedAt: time.Now().UTC(),
	})
	return s.saveUnlocked()
}

// Remove drops an entry. Used only by an explicit "un-revoke" administrative
// action. Returns nil if the serial was absent.
func (s *CRLStore) Remove(serial string) error {
	serial = normalizeSerial(serial)
	if serial == "" {
		return fmt.Errorf("serial must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.entries {
		if e.SerialHex == serial {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			return s.saveUnlocked()
		}
	}
	return nil
}

// Has reports whether the given serial is currently revoked. webui doesn't
// need this for live filtering (tls-proxy is the enforcement point), but it
// is handy for tests and for the admin UI badge.
func (s *CRLStore) Has(serial string) bool {
	serial = normalizeSerial(serial)
	if serial == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.SerialHex == serial {
			return true
		}
	}
	return false
}

// List returns a copy of all revoked entries in insertion order.
func (s *CRLStore) List() []RevokedEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RevokedEntry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Reload re-reads the file from disk, used by handlers that want to surface
// updates written by tls-proxy (currently unused — tls-proxy only reads the
// CRL — but kept for future symmetry).
func (s *CRLStore) Reload() error {
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
