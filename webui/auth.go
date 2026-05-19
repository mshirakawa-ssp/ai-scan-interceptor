package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role defines the two dashboard roles.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// sessionCookieName is the name of the HTTP cookie carrying the session token.
const sessionCookieName = "ai_scan_session"

// sessionTTL is how long a login session remains valid without activity.
const sessionTTL = 8 * time.Hour

// minPasswordLen enforces a minimum password length.
const minPasswordLen = 12

// User is a dashboard user stored in users.json.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	// FailedLogins tracks consecutive failures for lockout (not persisted across restarts).
	FailedLogins int       `json:"-"`
	LockedUntil  time.Time `json:"-"`
}

// Session represents an authenticated browser session.
type Session struct {
	Token     string
	UserID    string
	Username  string
	Role      Role
	ExpiresAt time.Time
}

// contextKey is an unexported type for context values set by auth middleware.
type contextKey int

const sessionCtxKey contextKey = 0

// ---- UserStore ----

// UserStore is a thread-safe, file-backed store of dashboard users.
type UserStore struct {
	mu    sync.RWMutex
	path  string
	users map[string]*User // keyed by ID
}

func newUserStore(path string) (*UserStore, error) {
	s := &UserStore{path: path, users: make(map[string]*User)}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load users: %w", err)
	}
	if len(s.users) == 0 {
		s.createDefaultAdmin()
	}
	return s, nil
}

// createDefaultAdmin generates a random admin password on first startup.
func (s *UserStore) createDefaultAdmin() {
	password := generateToken(10) // 20 hex chars → well above minPasswordLen
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("[auth] bcrypt: %v", err)
	}
	admin := &User{
		ID:           generateToken(16),
		Username:     "admin",
		PasswordHash: string(hash),
		Role:         RoleAdmin,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	s.users[admin.ID] = admin
	if err := s.saveUnlocked(); err != nil {
		log.Fatalf("[auth] save users: %v", err)
	}
	log.Printf("[auth] ========================================================")
	log.Printf("[auth]  DEFAULT ADMIN CREATED")
	log.Printf("[auth]  username : admin")
	log.Printf("[auth]  password : %s", password)
	log.Printf("[auth]  CHANGE THIS PASSWORD AFTER FIRST LOGIN")
	log.Printf("[auth] ========================================================")
}

func (s *UserStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var users []*User
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}
	for _, u := range users {
		s.users[u.ID] = u
	}
	return nil
}

func (s *UserStore) saveUnlocked() error {
	users := make([]*User, 0, len(s.users))
	for _, u := range users {
		users = append(users, u)
	}
	// rebuild from map
	users = users[:0]
	for _, u := range s.users {
		users = append(users, u)
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func (s *UserStore) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveUnlocked()
}

// Authenticate checks credentials and returns the matching user.
// It enforces per-account lockout after 10 consecutive failures.
func (s *UserStore) Authenticate(username, password string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var found *User
	for _, u := range s.users {
		if u.Username == username {
			found = u
			break
		}
	}
	if found == nil {
		// Constant-time dummy compare to prevent username enumeration via timing.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234"), []byte(password))
		return nil, fmt.Errorf("invalid credentials")
	}

	if time.Now().Before(found.LockedUntil) {
		return nil, fmt.Errorf("account locked; try again after %s", found.LockedUntil.Format(time.RFC3339))
	}

	if err := bcrypt.CompareHashAndPassword([]byte(found.PasswordHash), []byte(password)); err != nil {
		found.FailedLogins++
		if found.FailedLogins >= 10 {
			found.LockedUntil = time.Now().Add(30 * time.Minute)
			log.Printf("[auth] account locked after %d failures: username=%s locked_until=%s",
				found.FailedLogins, username, found.LockedUntil.Format(time.RFC3339))
		}
		return nil, fmt.Errorf("invalid credentials")
	}

	found.FailedLogins = 0
	return found, nil
}

// GetAll returns a copy of all users (without password hashes).
func (s *UserStore) GetAll() []UserInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UserInfo, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, UserInfo{ID: u.ID, Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt})
	}
	return out
}

// GetByID returns the user with the given ID, or (nil, false).
func (s *UserStore) GetByID(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

// Create adds a new user. Returns error if username already exists.
func (s *UserStore) Create(username, password string, role Role) (*User, error) {
	if len(password) < minPasswordLen {
		return nil, fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if role != RoleAdmin && role != RoleUser {
		return nil, fmt.Errorf("invalid role: %s", role)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Username == username {
			return nil, fmt.Errorf("username already exists")
		}
	}
	now := time.Now().UTC()
	u := &User{
		ID:           generateToken(16),
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.users[u.ID] = u
	return u, s.saveUnlocked()
}

// UpdateRole changes the role of a user.
func (s *UserStore) UpdateRole(id string, role Role) error {
	if role != RoleAdmin && role != RoleUser {
		return fmt.Errorf("invalid role: %s", role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.Role = role
	u.UpdatedAt = time.Now().UTC()
	return s.saveUnlocked()
}

// UpdatePassword changes a user's password.
func (s *UserStore) UpdatePassword(id, newPassword string) error {
	if len(newPassword) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.PasswordHash = string(hash)
	u.UpdatedAt = time.Now().UTC()
	return s.saveUnlocked()
}

// Delete removes a user by ID.
func (s *UserStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		return fmt.Errorf("user not found")
	}
	delete(s.users, id)
	return s.saveUnlocked()
}

// UnlockUser resets the account lockout state for the given user ID.
func (s *UserStore) UnlockUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.FailedLogins = 0
	u.LockedUntil = time.Time{}
	return nil
}

// UnlockUserByName resets lockout for the given username (used by CLI unlock tool).
func (s *UserStore) UnlockUserByName(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Username == username {
			u.FailedLogins = 0
			u.LockedUntil = time.Time{}
			return nil
		}
	}
	return fmt.Errorf("user %q not found", username)
}

// AdminCount returns the number of admin users (used to prevent deleting the last admin).
func (s *UserStore) AdminCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, u := range s.users {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

// UserInfo is a safe projection of User without the password hash.
type UserInfo struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// ---- SessionStore ----

// SessionStore holds in-memory sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

var globalSessions = &SessionStore{sessions: make(map[string]*Session)}

// Create issues a new session token for a user.
func (ss *SessionStore) Create(u *User) string {
	token := generateToken(32)
	sess := &Session{
		Token:     token,
		UserID:    u.ID,
		Username:  u.Username,
		Role:      u.Role,
		ExpiresAt: time.Now().Add(sessionTTL),
	}
	ss.mu.Lock()
	ss.sessions[token] = sess
	ss.mu.Unlock()
	return token
}

// Get returns the session for the given token, if valid and not expired.
func (ss *SessionStore) Get(token string) (*Session, bool) {
	ss.mu.RLock()
	sess, ok := ss.sessions[token]
	ss.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.ExpiresAt) {
		ss.Delete(token)
		return nil, false
	}
	return sess, true
}

// Delete invalidates a session token.
func (ss *SessionStore) Delete(token string) {
	ss.mu.Lock()
	delete(ss.sessions, token)
	ss.mu.Unlock()
}

// DeleteByUserID invalidates all sessions for a given user (e.g. on delete or role change).
func (ss *SessionStore) DeleteByUserID(userID string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for t, s := range ss.sessions {
		if s.UserID == userID {
			delete(ss.sessions, t)
		}
	}
}

// ---- Rate limiter (IP-based brute force protection) ----

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

type rateBucket struct {
	failures  int
	resetAt   time.Time
}

const (
	rateLimitWindow   = 15 * time.Minute
	rateLimitMaxTries = 5
)

var loginRateLimiter = &rateLimiter{buckets: make(map[string]*rateBucket)}

// Allow returns true if the IP is allowed to attempt a login.
// Successful logins always bypass the IP rate limit (see AllowOrAuthenticated).
func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[ip]
	if !ok || time.Now().After(b.resetAt) {
		rl.buckets[ip] = &rateBucket{failures: 0, resetAt: time.Now().Add(rateLimitWindow)}
		return true
	}
	return b.failures < rateLimitMaxTries
}

// ClearIP removes the rate-limit record for the given IP.
func (rl *rateLimiter) ClearIP(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, ip)
}

// ClearAll removes all IP rate-limit records (admin emergency action).
func (rl *rateLimiter) ClearAll() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.buckets = make(map[string]*rateBucket)
}

// RecordFailure increments the failure counter for an IP.
func (rl *rateLimiter) RecordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[ip]
	if !ok || time.Now().After(b.resetAt) {
		rl.buckets[ip] = &rateBucket{failures: 1, resetAt: time.Now().Add(rateLimitWindow)}
		return
	}
	b.failures++
}

// RecordSuccess resets the failure counter for an IP on successful login.
func (rl *rateLimiter) RecordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, ip)
}

// ---- Helpers ----

func generateToken(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
