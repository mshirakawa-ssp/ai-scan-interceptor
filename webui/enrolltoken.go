package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// EnrollToken is a one-time (or limited-use) token that the AI-Scan-Connect
// agent presents to tls-proxy /enroll to obtain a signed device certificate.
//
// The plaintext token is returned only once (at creation time). Only the SHA-256
// hash is persisted, so a leak of enroll-tokens.json does not let an attacker
// enroll new devices.
type EnrollToken struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	TokenHash   string     `json:"token_hash"` // SHA-256 hex of the plaintext token
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
	ExpiresAt   time.Time  `json:"expires_at"`
	MaxUses     int        `json:"max_uses"`
	UsedCount   int        `json:"used_count"`
	Revoked     bool       `json:"revoked"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// flockTimeout caps how long a webui issuer waits to acquire the cross-process
// flock against tls-proxy's consumer path. 5s is plenty given enroll bursts
// are seconds apart in practice.
const flockTimeout = 5 * time.Second

// EnrollTokenStore is a thread-safe, file-backed list of enrollment tokens.
//
// Cross-process safety: all mutating operations (Create / Revoke / Delete)
// acquire an exclusive flock on path+".lock" before doing read-modify-write
// on path. The same lock file is used by tls-proxy when it bumps used_count
// during /enroll consumption — see PLAN_CONNECT_MTLS.md for the contract.
//
// Inside the flock we re-read the JSON file before mutating so concurrent
// writes from tls-proxy (used_count++) are not lost.
type EnrollTokenStore struct {
	mu       sync.RWMutex // guards in-memory tokens for fast List/GetByID
	path     string
	lockPath string
	tokens   []*EnrollToken
}

func newEnrollTokenStore(path string) (*EnrollTokenStore, error) {
	s := &EnrollTokenStore{
		path:     path,
		lockPath: path + ".lock",
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load enroll tokens: %w", err)
	}
	return s, nil
}

// load is used at startup (no lock needed yet) and inside the flock to refresh
// in-memory state from disk before mutating.
func (s *EnrollTokenStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		s.mu.Lock()
		s.tokens = nil
		s.mu.Unlock()
		return nil
	}
	var tokens []*EnrollToken
	if err := json.Unmarshal(data, &tokens); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = tokens
	return nil
}

// reloadFromDiskUnlocked refreshes s.tokens from disk without acquiring the
// in-memory mutex. Caller must hold s.mu.
func (s *EnrollTokenStore) reloadFromDiskUnlocked() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.tokens = nil
			return nil
		}
		return err
	}
	if len(data) == 0 {
		s.tokens = nil
		return nil
	}
	var tokens []*EnrollToken
	if err := json.Unmarshal(data, &tokens); err != nil {
		return fmt.Errorf("reload parse: %w", err)
	}
	s.tokens = tokens
	return nil
}

// saveUnlocked persists the current token list. Caller must hold s.mu (and the
// cross-process flock for cross-process safety against tls-proxy).
func (s *EnrollTokenStore) saveUnlocked() error {
	if s.tokens == nil {
		s.tokens = []*EnrollToken{}
	}
	data, err := json.MarshalIndent(s.tokens, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.path, data, 0600)
}

// CreateOptions describes a new enrollment token request.
type CreateOptions struct {
	Description    string
	ExpiresInHours int
	MaxUses        int
	CreatedBy      string
}

// Create issues a new token. Returns the persisted record (with hash only) and
// the plaintext token string — the plaintext is shown to the admin once and
// never stored.
//
// The whole read-modify-write happens inside a flock against tls-proxy.
func (s *EnrollTokenStore) Create(opt CreateOptions) (*EnrollToken, string, error) {
	if opt.ExpiresInHours <= 0 {
		opt.ExpiresInHours = 24
	}
	if opt.ExpiresInHours > 24*30 {
		return nil, "", errors.New("expires_in_hours must be <= 720 (30 days)")
	}
	if opt.MaxUses <= 0 {
		opt.MaxUses = 1
	}
	if opt.MaxUses > 1000 {
		return nil, "", errors.New("max_uses must be <= 1000")
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("rand: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now().UTC()
	id := generateToken(8) // 16 hex chars; collision-resistant for our scale

	tok := &EnrollToken{
		ID:          id,
		Description: opt.Description,
		TokenHash:   hashToken(plaintext),
		CreatedAt:   now,
		CreatedBy:   opt.CreatedBy,
		ExpiresAt:   now.Add(time.Duration(opt.ExpiresInHours) * time.Hour),
		MaxUses:     opt.MaxUses,
		UsedCount:   0,
	}

	err := WithFlock(s.lockPath, flockTimeout, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		// Pull in any concurrent writes from tls-proxy (used_count++).
		if err := s.reloadFromDiskUnlocked(); err != nil {
			return err
		}
		s.tokens = append(s.tokens, tok)
		if err := s.saveUnlocked(); err != nil {
			// Roll back the in-memory append on persistence failure.
			s.tokens = s.tokens[:len(s.tokens)-1]
			return fmt.Errorf("persist: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return tok, plaintext, nil
}

// hashToken returns the SHA-256 hex digest of s.
func hashToken(s string) string {
	sum := sha256Sum([]byte(s))
	return fmt.Sprintf("%x", sum[:])
}

// List returns a copy of all stored tokens (without plaintext, which is
// never persisted). Callers that need to surface fresh used_count values
// written by tls-proxy should call Reload first.
func (s *EnrollTokenStore) List() []EnrollToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]EnrollToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, *t)
	}
	return out
}

// Reload re-reads the file from disk under flock so the caller's next List()
// sees writes from tls-proxy. Used by GET /api/enroll-tokens.
func (s *EnrollTokenStore) Reload() error {
	return WithFlock(s.lockPath, flockTimeout, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.reloadFromDiskUnlocked()
	})
}

// GetByID returns a copy of the token with the given ID.
func (s *EnrollTokenStore) GetByID(id string) (EnrollToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tokens {
		if t.ID == id {
			return *t, true
		}
	}
	return EnrollToken{}, false
}

// Revoke marks a token revoked. It remains in the list as an audit record.
// Cross-process safe via flock.
func (s *EnrollTokenStore) Revoke(id string) error {
	return WithFlock(s.lockPath, flockTimeout, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.reloadFromDiskUnlocked(); err != nil {
			return err
		}
		for _, t := range s.tokens {
			if t.ID == id {
				if t.Revoked {
					return nil
				}
				now := time.Now().UTC()
				t.Revoked = true
				t.RevokedAt = &now
				return s.saveUnlocked()
			}
		}
		return errors.New("not found")
	})
}

// Delete permanently removes the token record. Prefer Revoke for audit trail;
// Delete is exposed only for tests / admin cleanup. Cross-process safe via flock.
func (s *EnrollTokenStore) Delete(id string) error {
	return WithFlock(s.lockPath, flockTimeout, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.reloadFromDiskUnlocked(); err != nil {
			return err
		}
		for i, t := range s.tokens {
			if t.ID == id {
				s.tokens = append(s.tokens[:i], s.tokens[i+1:]...)
				return s.saveUnlocked()
			}
		}
		return errors.New("not found")
	})
}
