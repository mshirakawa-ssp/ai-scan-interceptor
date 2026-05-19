package main

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed static
var staticFiles embed.FS

// LogEntry mirrors the icap-server storage.LogEntry structure.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Service   string    `json:"service"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Prompt    string    `json:"prompt"`
	Triggered bool      `json:"triggered"`
	Severity  string    `json:"severity,omitempty"`
	RuleIDs   []string  `json:"rule_ids,omitempty"`
	ClientIP  string    `json:"client_ip"`
	UserID    string    `json:"user_id,omitempty"`
	Action    string    `json:"action,omitempty"`
}

// securityHeaders is middleware that sets hardening HTTP response headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Strict CSP: no inline scripts/styles, no external resources.
		// 'unsafe-inline' is intentionally omitted; the dashboard uses no inline event handlers.
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func registerHandlers(mux *http.ServeMux, logDir string, configDir string, users *UserStore, logSettings *LogSettingsStore, notifSettings *NotificationSettingsStore, orgCA *OrgCA, enrollTokens *EnrollTokenStore, devices *DeviceStore, crl *CRLStore) {
	// Serve static files
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("[webui] failed to create sub FS: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Auth endpoints (no authentication required)
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		handleLogin(w, r, users)
	})
	mux.HandleFunc("/api/auth/logout", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleLogout(w, r)
	}))
	mux.HandleFunc("/api/auth/me", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleMe(w, r)
	}))

	// User management (admin only)
	mux.HandleFunc("/api/users", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleUsers(w, r, users)
	}))
	mux.HandleFunc("/api/users/", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleUserByID(w, r, users)
	}))
	// Log retention settings (admin only)
	mux.HandleFunc("/api/settings", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleLogSettings(w, r, logSettings)
	}))
	// Notification settings (admin only)
	mux.HandleFunc("/api/notification", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleNotificationSettings(w, r, notifSettings)
	}))

	// Rate-limit management (admin only)
	mux.HandleFunc("/api/auth/rate-limits", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		loginRateLimiter.ClearAll()
		actor := sessionFromCtx(r)
		log.Printf("[auth] rate limits cleared by admin: user=%s", actor.Username)
		w.WriteHeader(http.StatusNoContent)
	}))

	// Protected API endpoints (any authenticated user)
	mux.HandleFunc("/api/logs", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleLogs(w, r, logDir)
	}))
	mux.HandleFunc("/api/policy", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlePolicy(w, r, configDir)
	}))
	// /api/rules/reset must be registered BEFORE /api/rules/ to avoid routing conflicts.
	mux.HandleFunc("/api/rules/reset", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleRulesReset(w, r, configDir)
	}))
	mux.HandleFunc("/api/rules", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleRules(w, r, configDir)
	}))
	mux.HandleFunc("/api/rules/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleRuleByID(w, r, configDir)
	}))

	// Organization CA certificate (admin only).
	mux.HandleFunc("/api/org-ca/cert", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleOrgCACert(w, r, orgCA)
	}))

	// Enrollment tokens (admin only).
	mux.HandleFunc("/api/enroll-tokens", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleEnrollTokens(w, r, enrollTokens)
	}))
	mux.HandleFunc("/api/enroll-tokens/", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleEnrollTokenByID(w, r, enrollTokens)
	}))

	// Device registry (admin only).
	mux.HandleFunc("/api/devices", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleDevices(w, r, devices)
	}))
	mux.HandleFunc("/api/devices/", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleDeviceByID(w, r, devices)
	}))

	// CRL view (admin only). Read-only; revocation is performed via /api/devices/{id}/revoke.
	mux.HandleFunc("/api/revoked", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		handleRevoked(w, r, crl)
	}))
}

// handleRevoked returns the current revoked-serials list (admin only).
func handleRevoked(w http.ResponseWriter, r *http.Request, crl *CRLStore) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Refresh from disk in case an external process (future tooling) updated it.
	if err := crl.Reload(); err != nil {
		log.Printf("[crl] reload error: %v", err)
		// fall through with in-memory state
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(crl.List())
}

// ---- Org CA / enrollment / device handlers ----

// handleOrgCACert returns the PEM-encoded organization CA certificate plus
// metadata. Admin-only.
func handleOrgCACert(w http.ResponseWriter, r *http.Request, ca *OrgCA) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"subject":     ca.Subject(),
		"not_after":   ca.NotAfter(),
		"fingerprint": ca.Fingerprint(),
		"cert_pem":    string(ca.CertPEM()),
	})
}

// handleEnrollTokens handles GET (list) and POST (create) on /api/enroll-tokens.
func handleEnrollTokens(w http.ResponseWriter, r *http.Request, store *EnrollTokenStore) {
	switch r.Method {
	case http.MethodGet:
		// Refresh from disk so used_count reflects writes from tls-proxy.
		if err := store.Reload(); err != nil {
			log.Printf("[enroll] reload error: %v", err)
			// fall through with in-memory snapshot
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.List())

	case http.MethodPost:
		var req struct {
			Description    string `json:"description"`
			ExpiresInHours int    `json:"expires_in_hours"`
			MaxUses        int    `json:"max_uses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		actor := sessionFromCtx(r)
		tok, plaintext, err := store.Create(CreateOptions{
			Description:    req.Description,
			ExpiresInHours: req.ExpiresInHours,
			MaxUses:        req.MaxUses,
			CreatedBy:      actor.Username,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Build the Connect-side enrollment URL relative to the Host header.
		// Connect actually talks to tls-proxy:3128 (mTLS), not the webui port,
		// but we surface the host here so the admin sees the right deployment.
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		enrollURL := fmt.Sprintf("%s://%s/enroll", scheme, r.Host)
		log.Printf("[enroll] token created: id=%s by=%s desc=%q max_uses=%d",
			tok.ID, actor.Username, tok.Description, tok.MaxUses)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          tok.ID,
			"description": tok.Description,
			"token":       plaintext, // shown ONCE; not stored
			"expires_at":  tok.ExpiresAt,
			"max_uses":    tok.MaxUses,
			"created_at":  tok.CreatedAt,
			"url":         enrollURL,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEnrollTokenByID handles DELETE (revoke) on /api/enroll-tokens/{id}.
func handleEnrollTokenByID(w http.ResponseWriter, r *http.Request, store *EnrollTokenStore) {
	id := strings.TrimPrefix(r.URL.Path, "/api/enroll-tokens/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "missing or invalid token id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := store.Revoke(id); err != nil {
			if err.Error() == "not found" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		actor := sessionFromCtx(r)
		log.Printf("[enroll] token revoked: id=%s by=%s", id, actor.Username)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDevices handles GET /api/devices (list).
func handleDevices(w http.ResponseWriter, r *http.Request, store *DeviceStore) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Re-read file under read lock so we see writes from tls-proxy.
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		log.Printf("[devices] reload error: %v", err)
		// Fall through with whatever is in memory.
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(store.List())
}

// handleDeviceByID handles:
//   - GET    /api/devices/{id}        — detail
//   - POST   /api/devices/{id}/revoke — revoke
func handleDeviceByID(w http.ResponseWriter, r *http.Request, store *DeviceStore) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/devices/")
	var id, sub string
	if idx := strings.Index(rest, "/"); idx >= 0 {
		id = rest[:idx]
		sub = rest[idx+1:]
	} else {
		id = rest
	}
	if id == "" {
		http.Error(w, "missing device id", http.StatusBadRequest)
		return
	}

	switch {
	case sub == "" && r.Method == http.MethodGet:
		if err := store.load(); err != nil && !os.IsNotExist(err) {
			log.Printf("[devices] reload error: %v", err)
		}
		d, ok := store.GetByID(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)

	case sub == "revoke" && r.Method == http.MethodPost:
		if err := store.Revoke(id); err != nil {
			if err == ErrDeviceNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		actor := sessionFromCtx(r)
		log.Printf("[devices] revoked: id=%s by=%s", id, actor.Username)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- Auth middleware ----

// requireAuth wraps a handler to reject unauthenticated requests with 401.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		sess, ok := globalSessions.Get(cookie.Value)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey, sess)
		next(w, r.WithContext(ctx))
	}
}

// requireAdmin wraps a handler to reject non-admin sessions with 403.
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return requireAuth(func(w http.ResponseWriter, r *http.Request) {
		sess := r.Context().Value(sessionCtxKey).(*Session)
		if sess.Role != RoleAdmin {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// sessionFromCtx extracts the session placed in context by requireAuth.
func sessionFromCtx(r *http.Request) *Session {
	s, _ := r.Context().Value(sessionCtxKey).(*Session)
	return s
}

// clientIP returns the remote IP address without the port, for rate limiting.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- Auth handlers ----

func handleLogin(w http.ResponseWriter, r *http.Request, users *UserStore) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r)
	if !loginRateLimiter.Allow(ip) {
		w.Header().Set("Content-Type", "application/json")
		// Fixed delay to slow down automated tools.
		time.Sleep(2 * time.Second)
		http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		loginRateLimiter.RecordFailure(ip)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	user, err := users.Authenticate(req.Username, req.Password)
	if err != nil {
		loginRateLimiter.RecordFailure(ip)
		log.Printf("[auth] login failed: username=%s ip=%s err=%v", req.Username, ip, err)
		// Always return the same error message to prevent username enumeration.
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	loginRateLimiter.RecordSuccess(ip)
	token := globalSessions.Create(user)
	log.Printf("[auth] login: username=%s role=%s ip=%s", user.Username, user.Role, ip)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // set to true when serving over HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := sessionFromCtx(r)
	if sess != nil {
		globalSessions.Delete(sess.Token)
		log.Printf("[auth] logout: username=%s", sess.Username)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := sessionFromCtx(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       sess.UserID,
		"username": sess.Username,
		"role":     sess.Role,
	})
}

// ---- User management handlers (admin only) ----

func handleUsers(w http.ResponseWriter, r *http.Request, users *UserStore) {
	switch r.Method {
	case http.MethodGet:
		all := users.GetAll()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(all)

	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     Role   `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Username == "" {
			http.Error(w, "username required", http.StatusBadRequest)
			return
		}
		u, err := users.Create(req.Username, req.Password, req.Role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("[auth] user created: username=%s role=%s by=%s",
			u.Username, u.Role, sessionFromCtx(r).Username)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(UserInfo{ID: u.ID, Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleUserByID(w http.ResponseWriter, r *http.Request, users *UserStore) {
	// URL: /api/users/{id} or /api/users/{id}/password
	rest := strings.TrimPrefix(r.URL.Path, "/api/users/")
	var id, sub string
	if idx := strings.Index(rest, "/"); idx >= 0 {
		id = rest[:idx]
		sub = rest[idx+1:]
	} else {
		id = rest
	}
	if id == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}

	actor := sessionFromCtx(r)

	switch {
	case sub == "unlock" && r.Method == http.MethodPost:
		if err := users.UnlockUser(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		log.Printf("[auth] account unlocked: user_id=%s by=%s", id, actor.Username)
		w.WriteHeader(http.StatusNoContent)

	case sub == "password" && r.Method == http.MethodPut:
		// Allow users to change their own password; admins can change anyone's.
		if actor.Role != RoleAdmin && actor.UserID != id {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := users.UpdatePassword(id, req.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		globalSessions.DeleteByUserID(id) // invalidate active sessions on password change
		log.Printf("[auth] password changed: user_id=%s by=%s", id, actor.Username)
		w.WriteHeader(http.StatusNoContent)

	case sub == "" && r.Method == http.MethodPut:
		var req struct {
			Role Role `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Prevent demoting self.
		if actor.UserID == id && req.Role != RoleAdmin {
			http.Error(w, "cannot demote your own account", http.StatusBadRequest)
			return
		}
		if err := users.UpdateRole(id, req.Role); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		globalSessions.DeleteByUserID(id) // invalidate sessions so role takes effect immediately
		log.Printf("[auth] role updated: user_id=%s new_role=%s by=%s", id, req.Role, actor.Username)
		w.WriteHeader(http.StatusNoContent)

	case sub == "" && r.Method == http.MethodDelete:
		// Prevent deleting self.
		if actor.UserID == id {
			http.Error(w, "cannot delete your own account", http.StatusBadRequest)
			return
		}
		// Prevent deleting the last admin.
		u, ok := users.GetByID(id)
		if ok && u.Role == RoleAdmin && users.AdminCount() <= 1 {
			http.Error(w, "cannot delete the last admin account", http.StatusBadRequest)
			return
		}
		if err := users.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		globalSessions.DeleteByUserID(id)
		log.Printf("[auth] user deleted: user_id=%s by=%s", id, actor.Username)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// WithSecurityHeaders wraps a handler with the securityHeaders middleware.
// Call this on the top-level mux in main so all routes are covered.
func WithSecurityHeaders(h http.Handler) http.Handler {
	return securityHeaders(h)
}

func handleLogs(w http.ResponseWriter, r *http.Request, logDir string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	filterService := q.Get("service")
	filterSeverity := q.Get("severity")
	filterTriggered := q.Get("triggered")
	filterText := strings.ToLower(q.Get("q"))
	filterHost := strings.ToLower(q.Get("host"))
	filterUser := strings.ToLower(q.Get("user_id"))

	// Excluded services: comma-separated list of service names to hide.
	var excludeServices []string
	if raw := q.Get("exclude_service"); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			if t := strings.TrimSpace(s); t != "" {
				excludeServices = append(excludeServices, strings.ToLower(t))
			}
		}
	}

	entries, err := readAllLogs(logDir)
	if err != nil {
		log.Printf("[webui] error reading logs: %v", err)
		http.Error(w, "failed to read logs", http.StatusInternalServerError)
		return
	}

	// Sort by timestamp descending (most recent first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	// Apply filters
	filtered := make([]LogEntry, 0, len(entries))
	for _, e := range entries {
		if filterService != "" && !strings.EqualFold(e.Service, filterService) {
			continue
		}
		if filterSeverity != "" && !strings.EqualFold(e.Severity, filterSeverity) {
			continue
		}
		if filterTriggered == "true" && !e.Triggered {
			continue
		}
		if filterText != "" && !matchesText(e, filterText) {
			continue
		}
		if len(excludeServices) > 0 {
			svcLower := strings.ToLower(e.Service)
			excluded := false
			for _, ex := range excludeServices {
				if svcLower == ex {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}
		if filterHost != "" && !strings.Contains(strings.ToLower(e.Host), filterHost) {
			continue
		}
		if filterUser != "" && !strings.Contains(strings.ToLower(e.UserID), filterUser) {
			continue
		}
		filtered = append(filtered, e)
		if len(filtered) >= 500 {
			break
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(filtered); err != nil {
		log.Printf("[webui] error encoding response: %v", err)
	}
}

func matchesText(e LogEntry, q string) bool {
	if strings.Contains(strings.ToLower(e.Prompt), q) {
		return true
	}
	for _, rid := range e.RuleIDs {
		if strings.Contains(strings.ToLower(rid), q) {
			return true
		}
	}
	return false
}

// maxLogFiles caps how many JSONL files are read per request to bound memory usage.
// Each file can be up to 10 MB (icap-server rotation limit), so this caps peak
// in-memory log data at maxLogFiles * 10 MB before JSON unmarshalling overhead.
const maxLogFiles = 20

func readAllLogs(logDir string) ([]LogEntry, error) {
	pattern := filepath.Join(logDir, "*.jsonl")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	// Sort descending (most-recent files first) so the cap keeps the latest data.
	sort.Sort(sort.Reverse(sort.StringSlice(files)))

	if len(files) > maxLogFiles {
		log.Printf("[webui] %d log files found; reading only the %d most recent (cap=%d)",
			len(files), maxLogFiles, maxLogFiles)
		files = files[:maxLogFiles]
	}

	var entries []LogEntry
	for _, f := range files {
		// Guard against symlinks or non-regular files that may have been placed in logDir.
		info, statErr := os.Lstat(f)
		if statErr != nil || !info.Mode().IsRegular() {
			log.Printf("[webui] skipping non-regular file %s", f)
			continue
		}
		got, err := parseJSONL(f)
		if err != nil {
			log.Printf("[webui] skipping %s: %v", f, err)
			continue
		}
		entries = append(entries, got...)
	}
	return entries, nil
}

// validateLogDir verifies that logDir is an absolute path and that it resolves to
// itself (no symlink traversal). Returns an error string suitable for Fatal logging.
func validateLogDir(logDir string) error {
	if !filepath.IsAbs(logDir) {
		return fmt.Errorf("LOG_DIR must be an absolute path, got %q", logDir)
	}
	real, err := filepath.EvalSymlinks(logDir)
	if err != nil {
		return fmt.Errorf("LOG_DIR %q: %w", logDir, err)
	}
	if real != logDir {
		return fmt.Errorf("LOG_DIR %q resolves to %q via symlink; use the real path", logDir, real)
	}
	return nil
}

// validateConfigDir verifies that configDir is an absolute path and that it resolves
// to itself (no symlink traversal). Returns an error suitable for Fatal logging.
func validateConfigDir(configDir string) error {
	if !filepath.IsAbs(configDir) {
		return fmt.Errorf("CONFIG_DIR must be an absolute path, got %q", configDir)
	}
	real, err := filepath.EvalSymlinks(configDir)
	if err != nil {
		return fmt.Errorf("CONFIG_DIR %q: %w", configDir, err)
	}
	if real != configDir {
		return fmt.Errorf("CONFIG_DIR %q resolves to %q via symlink; use the real path", configDir, real)
	}
	return nil
}

// PolicyConfig represents the policy.json structure.
type PolicyConfig struct {
	GlobalMode   string            `json:"global_mode"`
	ServiceModes map[string]string `json:"service_modes"`
	UpdatedAt    time.Time         `json:"updated_at,omitempty"`
}

var validModes = map[string]bool{"monitor": true, "warn": true, "block": true, "mask": true}

// RuleEntry mirrors the detection.RuleEntry structure for the unified rules store.
type RuleEntry struct {
	ID              string   `json:"id"`
	Source          string   `json:"source"` // "builtin" or "custom"
	Enabled         bool     `json:"enabled"`
	Severity        string   `json:"severity"`
	Description     string   `json:"description"`
	Pattern         string   `json:"pattern"`
	NegativeContext []string `json:"negative_context,omitempty"`
	MaskBody        bool     `json:"mask_body"`
}

var validRuleSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// builtinRuleEntries is a hardcoded copy of the built-in detection rules for
// POST /api/rules/reset (webui cannot import icap-server packages).
var builtinRuleEntries = []RuleEntry{
	{ID: "CRED-001", Source: "builtin", Enabled: true, Severity: "critical", Description: "OpenAI API key", Pattern: `sk-(?:proj|org)?-?[a-zA-Z0-9\-_]{20,}`, MaskBody: true},
	{ID: "CRED-002", Source: "builtin", Enabled: true, Severity: "critical", Description: "Anthropic API key", Pattern: `sk-ant-api\d{2}-[a-zA-Z0-9\-_]{20,}`, MaskBody: true},
	{ID: "CRED-003", Source: "builtin", Enabled: true, Severity: "critical", Description: "AWS Access Key ID", Pattern: `(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[0-9A-Z]{16}`, MaskBody: true},
	{ID: "CRED-004", Source: "builtin", Enabled: true, Severity: "critical", Description: "AWS Secret Access Key", Pattern: `(?i)aws[_\-\s]{0,5}secret[_\-\s]{0,5}(access[_\-\s]{0,5})?key\s*[=:]\s*(?:\\?")?[A-Za-z0-9+/]{20,}`, MaskBody: true},
	{ID: "CRED-005", Source: "builtin", Enabled: true, Severity: "critical", Description: "GitHub personal access token", Pattern: `gh[pousr]_[A-Za-z0-9]{36,}`, MaskBody: true},
	{ID: "CRED-006", Source: "builtin", Enabled: true, Severity: "critical", Description: "Google API key", Pattern: `AIza[0-9A-Za-z\-_]{35}`, MaskBody: true},
	{ID: "CRED-007", Source: "builtin", Enabled: true, Severity: "critical", Description: "PEM private key", Pattern: `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, MaskBody: true},
	{ID: "CRED-008", Source: "builtin", Enabled: true, Severity: "critical", Description: "JWT bearer token", Pattern: `eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.`, MaskBody: true},
	{ID: "CRED-009", Source: "builtin", Enabled: true, Severity: "critical", Description: "AWS Session Token", Pattern: `(?i)(aws_session_token|x-amz-security-token)\s*[=:]\s*(?:\\?")?[A-Za-z0-9+/=]{50,}`, MaskBody: true},
	{ID: "CRED-101", Source: "builtin", Enabled: true, Severity: "high", Description: "Credential key-value assignment", Pattern: `(?i)(password|passwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|private[_\-]?key)\s*[:=]\s*\S{4,}`, NegativeContext: []string{`(?i)(how[_ ]to|example|sample|placeholder|<[a-z_]+>|\[your|{your|your_[a-z]|\$\{|:= ""|\s""$|\s''$)`}, MaskBody: true},
	{ID: "PII-101", Source: "builtin", Enabled: true, Severity: "high", Description: "Japanese confidentiality markers", Pattern: `機密|社外秘|極秘|秘密情報`, MaskBody: false},
	{ID: "PII-102", Source: "builtin", Enabled: true, Severity: "high", Description: "Credit/debit card number", Pattern: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`, MaskBody: true},
	{ID: "PII-103", Source: "builtin", Enabled: true, Severity: "high", Description: "Japanese My Number (個人番号)", Pattern: `(?i)(マイナンバー|個人番号|my.?number)\s*[：:是]?\s*\d[\d\-\s]{10,14}\d`, MaskBody: true},
	{ID: "KEYWORD-201", Source: "builtin", Enabled: true, Severity: "medium", Description: "Password in disclosure context", Pattern: `(?i)\bpassword\b`, NegativeContext: []string{`(?i)(how (to|do|can|should)|what is|validate|validation|minimum.{0,20}length|policy|example|sample|forgot|reset (your|my|the)|create.{0,10}password|password (strength|hint|recovery|manager|field|input|policy|hash|encrypt|check|require)|set.{0,5}password\s*$)`}, MaskBody: false},
	{ID: "KEYWORD-202", Source: "builtin", Enabled: true, Severity: "medium", Description: "Internal-use or confidential label", Pattern: `(?i)(internal use only|社内限り|confidential -|for internal)`, MaskBody: false},
	{ID: "KEYWORD-203", Source: "builtin", Enabled: true, Severity: "medium", Description: "Authentication token in context", Pattern: `(?i)\b(bearer|auth|authorization)\s+[a-zA-Z0-9\-_+/]{16,}`, MaskBody: true},
}

func handlePolicy(w http.ResponseWriter, r *http.Request, configDir string) {
	// Path is fixed; no user input is used to construct it.
	policyPath := configDir + "/policy.json"

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(policyPath)
		if err != nil {
			if os.IsNotExist(err) {
				// Return default policy when file does not exist.
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"global_mode":"monitor","service_modes":{}}`))
				return
			}
			log.Printf("[webui] error reading policy: %v", err)
			http.Error(w, "failed to read policy", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(data)

	case http.MethodPut:
		var req struct {
			GlobalMode   string            `json:"global_mode"`
			ServiceModes map[string]string `json:"service_modes"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Validate global_mode
		if !validModes[req.GlobalMode] {
			http.Error(w, "invalid global_mode value", http.StatusBadRequest)
			return
		}
		// Validate service_modes
		for svc, mode := range req.ServiceModes {
			if !validModes[mode] {
				http.Error(w, "invalid mode for service "+svc, http.StatusBadRequest)
				return
			}
		}

		cfg := PolicyConfig{
			GlobalMode:   req.GlobalMode,
			ServiceModes: req.ServiceModes,
			UpdatedAt:    time.Now().UTC(),
		}
		if cfg.ServiceModes == nil {
			cfg.ServiceModes = map[string]string{}
		}

		out, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			log.Printf("[webui] error marshalling policy: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(policyPath, out, 0600); err != nil {
			log.Printf("[webui] error writing policy: %v", err)
			http.Error(w, "failed to write policy", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// readRules reads rules.json, returning an empty slice if the file does not exist.
func readRules(path string) ([]RuleEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []RuleEntry{}, nil
		}
		return nil, err
	}
	var rules []RuleEntry
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// writeRules persists the rules slice to disk with 0600 permissions.
func writeRules(path string, rules []RuleEntry) error {
	out, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0600)
}

// validateNewRule checks ID uniqueness, severity, and regex compilability for a new rule.
func validateNewRule(r RuleEntry, existing []RuleEntry) string {
	if r.ID == "" {
		return "id must not be empty"
	}
	if !validRuleSeverities[r.Severity] {
		return "invalid severity: must be critical, high, medium, or low"
	}
	if _, err := regexp.Compile(r.Pattern); err != nil {
		return "invalid regex pattern: " + err.Error()
	}
	for _, ex := range existing {
		if ex.ID == r.ID {
			return "id " + r.ID + " already exists"
		}
	}
	return ""
}

// handleRules handles GET /api/rules and POST /api/rules.
func handleRules(w http.ResponseWriter, r *http.Request, configDir string) {
	rulesPath := configDir + "/rules.json"

	switch r.Method {
	case http.MethodGet:
		rules, err := readRules(rulesPath)
		if err != nil {
			log.Printf("[webui] error reading rules: %v", err)
			http.Error(w, "failed to read rules", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(rules); err != nil {
			log.Printf("[webui] error encoding rules: %v", err)
		}

	case http.MethodPost:
		var rule RuleEntry
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Force source to "custom" for new rules added via the API.
		rule.Source = "custom"
		existing, err := readRules(rulesPath)
		if err != nil {
			log.Printf("[webui] error reading rules: %v", err)
			http.Error(w, "failed to read rules", http.StatusInternalServerError)
			return
		}
		if msg := validateNewRule(rule, existing); msg != "" {
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		existing = append(existing, rule)
		if err := writeRules(rulesPath, existing); err != nil {
			log.Printf("[webui] error writing rules: %v", err)
			http.Error(w, "failed to write rules", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRuleByID handles PUT /api/rules/{id} and DELETE /api/rules/{id}.
func handleRuleByID(w http.ResponseWriter, r *http.Request, configDir string) {
	// Extract the id from the URL path: /api/rules/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if id == "" {
		http.Error(w, "missing rule id", http.StatusBadRequest)
		return
	}

	rulesPath := configDir + "/rules.json"

	switch r.Method {
	case http.MethodPut:
		var updated RuleEntry
		if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		rules, err := readRules(rulesPath)
		if err != nil {
			log.Printf("[webui] error reading rules: %v", err)
			http.Error(w, "failed to read rules", http.StatusInternalServerError)
			return
		}
		idx := -1
		for i, rule := range rules {
			if rule.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		// Validate the new pattern if it changed.
		if _, err := regexp.Compile(updated.Pattern); err != nil {
			http.Error(w, "invalid regex pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
		if updated.Severity != "" && !validRuleSeverities[updated.Severity] {
			http.Error(w, "invalid severity: must be critical, high, medium, or low", http.StatusBadRequest)
			return
		}
		// Preserve immutable fields: ID and Source (for builtin rules).
		updated.ID = rules[idx].ID
		updated.Source = rules[idx].Source
		rules[idx] = updated
		if err := writeRules(rulesPath, rules); err != nil {
			log.Printf("[webui] error writing rules: %v", err)
			http.Error(w, "failed to write rules", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		rules, err := readRules(rulesPath)
		if err != nil {
			log.Printf("[webui] error reading rules: %v", err)
			http.Error(w, "failed to read rules", http.StatusInternalServerError)
			return
		}
		newRules := rules[:0]
		found := false
		for _, rule := range rules {
			if rule.ID == id {
				found = true
				continue
			}
			newRules = append(newRules, rule)
		}
		if !found {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		if err := writeRules(rulesPath, newRules); err != nil {
			log.Printf("[webui] error writing rules: %v", err)
			http.Error(w, "failed to write rules", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRulesReset handles POST /api/rules/reset — overwrites rules.json with built-in defaults.
func handleRulesReset(w http.ResponseWriter, r *http.Request, configDir string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rulesPath := configDir + "/rules.json"
	if err := writeRules(rulesPath, builtinRuleEntries); err != nil {
		log.Printf("[webui] error writing rules on reset: %v", err)
		http.Error(w, "failed to reset rules", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseJSONL(path string) ([]LogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB per line buffer
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			log.Printf("[webui] skipping malformed line in %s: %v", path, err)
			continue
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

// handleNotificationSettings serves GET/PUT /api/notification (admin only).
func handleNotificationSettings(w http.ResponseWriter, r *http.Request, store *NotificationSettingsStore) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.GetMasked())
	case http.MethodPut:
		var ns NotificationSettings
		if err := json.NewDecoder(r.Body).Decode(&ns); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		actor := sessionFromCtx(r)
		if err := store.Set(ns); err != nil {
			log.Printf("[notification] save error: %v", err)
			http.Error(w, "failed to save settings", http.StatusInternalServerError)
			return
		}
		log.Printf("[notification] settings updated by %s", actor.Username)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLogSettings serves GET/PUT /api/settings (admin only).
func handleLogSettings(w http.ResponseWriter, r *http.Request, store *LogSettingsStore) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.Get())
	case http.MethodPut:
		var ls LogSettings
		if err := json.NewDecoder(r.Body).Decode(&ls); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		actor := sessionFromCtx(r)
		if err := store.Set(ls); err != nil {
			log.Printf("[settings] save error: %v", err)
			http.Error(w, "failed to save settings", http.StatusInternalServerError)
			return
		}
		log.Printf("[settings] retention_days updated to %d by %s", ls.RetentionDays, actor.Username)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
