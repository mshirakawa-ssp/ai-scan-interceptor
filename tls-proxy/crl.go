// crl.go: in-memory revocation list for mTLS client certs.
//
// The webui (writer side) maintains /config/revoked-serials.json with the
// schema:
//
//   {
//     "version": 1,
//     "revoked": [
//       {"serial_hex": "0a1b2c", "subject": "alice@WIN-042",
//        "revoked_at": "2026-05-09T10:00:00Z"}
//     ]
//   }
//
// tls-proxy is the reader side: it loads the file at startup and reloads
// every 30s. The mTLS handshake's VerifyPeerCertificate hook calls
// (*RevokedStore).IsRevoked on each peer cert serial; revoked serials cause
// the handshake to fail with a clear error.
//
// File-missing or empty file is treated as "no revocations" (not a fatal
// error), so the system stays available even before webui has written its
// first record.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// revokedFileSchema mirrors the on-disk format. Field names are fixed; do
// not change without updating the webui side too.
type revokedFileSchema struct {
	Version int             `json:"version"`
	Revoked []revokedRecord `json:"revoked"`
}

type revokedRecord struct {
	SerialHex string    `json:"serial_hex"`
	Subject   string    `json:"subject,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

// RevokedStore is a concurrent-safe set of revoked cert serials, keyed by
// lowercase hex (no leading "0x", no separators). Build via LoadRevokedStore
// and refresh via StartReloader.
type RevokedStore struct {
	mu       sync.RWMutex
	serials  map[string]bool
	loadedAt time.Time
}

// NewEmptyRevokedStore returns a RevokedStore with no entries. Useful for
// tests and as a fallback when MTLS_ENABLED is false.
func NewEmptyRevokedStore() *RevokedStore {
	return &RevokedStore{serials: map[string]bool{}}
}

// LoadRevokedStore reads path and returns a populated store. A missing or
// empty file is treated as "no revocations" and returns an empty store.
// Malformed JSON returns an error.
func LoadRevokedStore(path string) (*RevokedStore, error) {
	s := NewEmptyRevokedStore()
	if err := s.reloadFrom(path); err != nil {
		return nil, err
	}
	return s, nil
}

// reloadFrom rereads path and atomically swaps the in-memory map.
func (s *RevokedStore) reloadFrom(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.mu.Lock()
			s.serials = map[string]bool{}
			s.loadedAt = time.Now()
			s.mu.Unlock()
			return nil
		}
		return fmt.Errorf("read CRL %s: %w", path, err)
	}
	if len(data) == 0 {
		s.mu.Lock()
		s.serials = map[string]bool{}
		s.loadedAt = time.Now()
		s.mu.Unlock()
		return nil
	}
	var schema revokedFileSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return fmt.Errorf("parse CRL %s: %w", path, err)
	}
	next := make(map[string]bool, len(schema.Revoked))
	for _, r := range schema.Revoked {
		k := normalizeSerialHex(r.SerialHex)
		if k == "" {
			continue
		}
		next[k] = true
	}
	s.mu.Lock()
	s.serials = next
	s.loadedAt = time.Now()
	s.mu.Unlock()
	return nil
}

// IsRevoked reports whether the given big.Int serial is on the revocation
// list. Lookup is case-insensitive on the hex form.
func (s *RevokedStore) IsRevoked(serial *big.Int) bool {
	if s == nil || serial == nil {
		return false
	}
	key := normalizeSerialHex(serial.Text(16))
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serials[key]
}

// IsRevokedHex is convenient for tests; same semantics as IsRevoked.
func (s *RevokedStore) IsRevokedHex(serialHex string) bool {
	if s == nil {
		return false
	}
	key := normalizeSerialHex(serialHex)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serials[key]
}

// Size returns the number of revoked serials currently loaded. Test-only.
func (s *RevokedStore) Size() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.serials)
}

// LoadedAt reports the time of the most recent successful (re)load.
func (s *RevokedStore) LoadedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadedAt
}

// StartReloader spawns a goroutine that calls reloadFrom every interval
// until ctx is cancelled. Errors are logged but do not stop the loop —
// the previously loaded set stays in effect on transient read failures.
func (s *RevokedStore) StartReloader(ctx context.Context, path string, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.reloadFrom(path); err != nil {
					log.Printf("[tls-proxy] CRL reload %s: %v", path, err)
				}
			}
		}
	}()
}

// normalizeSerialHex coerces the input to the canonical form used as the
// map key: lowercase, no separators, no leading "0x", and with leading
// zeros stripped (matching big.Int.Text(16) semantics). Empty / non-hex
// inputs are coerced to "" so they never match a real serial.
//
// We canonicalise to "no leading zeros" because (*big.Int).Text(16) does
// the same, and IsRevoked feeds that form into the map. This means
// "0a1b2c" in the CRL file matches the runtime serial 0x0a1b2c regardless
// of how either side chose to render leading zeros.
func normalizeSerialHex(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return ""
	}
	// Validate hex; if not valid, return "" so it never matches.
	if _, err := hex.DecodeString(padEvenLen(s)); err != nil {
		return ""
	}
	s = strings.ToLower(s)
	// Strip leading zeros to match big.Int.Text(16) output.
	stripped := strings.TrimLeft(s, "0")
	if stripped == "" {
		// All-zero serial. Unusual, but represent as "0".
		return "0"
	}
	return stripped
}

func padEvenLen(s string) string {
	if len(s)%2 != 0 {
		return "0" + s
	}
	return s
}
