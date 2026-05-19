// enroll.go: HTTP enrollment endpoint used by AI-Scan-Connect to obtain
// a short-lived client certificate signed by the organization CA.
//
// Flow:
//
//   1. The WebUI generates a one-time enrollment token and writes it to
//      /config/enroll-tokens.json (managed by webui).
//   2. AI-Scan-Connect, on first run, generates a key pair locally, builds
//      a CSR with Subject CN="user@host" O="<org>" and POSTs to /enroll
//      with the CSR and token.
//   3. tls-proxy validates the token, signs the CSR using the Org CA
//      (ORG_CA_FILE + ORG_CA_KEY_FILE), marks the token as consumed, and
//      returns the cert PEM plus the CA chain.
//
// Phase-1 limitations (intentional):
//   - No CRL / revocation; revocation is Phase 2.
//   - Token store is plain JSON; webui has its own locking semantics.
//   - 7-day cert lifetime; Connect renews automatically when <72h remain.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// enrollConfig is the runtime configuration for the enrollment endpoint.
type enrollConfig struct {
	Listen          string            // ENROLL_LISTEN, default ":3131"
	OrgCACert       *x509.Certificate // parsed ORG_CA_FILE
	OrgCAKey        *rsa.PrivateKey   // parsed ORG_CA_KEY_FILE
	OrgCAPEM        []byte            // raw PEM of ORG_CA_FILE for ca_chain field
	TokensFile      string            // /config/enroll-tokens.json
	TokensLockFile  string            // sidecar flock path; default <TokensFile>.lock
	DevicesFile     string            // /config/devices.json (shared with webui)
	DevicesLockFile string            // sidecar flock path; default <DevicesFile>.lock
	LockTimeout     time.Duration     // flock acquisition timeout; default 5s
	CertLifetime    time.Duration     // default 7 * 24h
}

// enrollToken is one record in /config/enroll-tokens.json.
//
// The webui writes these records when an admin pushes "issue enrollment
// token". tls-proxy reads/updates the same file on POST /enroll.
//
// {
//   "tokens": [
//     {"token":"...","org_id":"acme","user":"alice@laptop","expires_at":"...","consumed_at":"..."},
//     ...
//   ]
// }
type enrollToken struct {
	Token      string    `json:"token"`
	OrgID      string    `json:"org_id"`
	User       string    `json:"user,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	ConsumedAt time.Time `json:"consumed_at,omitempty"`
	// UsedCount tracks consume attempts for observability. tls-proxy
	// increments on each successful consume; webui may render this in the
	// admin UI. Not used for auth decisions (single-use is enforced via
	// ConsumedAt).
	UsedCount int `json:"used_count,omitempty"`
}

type enrollTokenStore struct {
	Tokens []enrollToken `json:"tokens"`
}

// enrollRequest is the JSON body of POST /enroll.
type enrollRequest struct {
	CSR             string `json:"csr"`              // PEM-encoded CertificateRequest
	EnrollmentToken string `json:"enrollment_token"` // token issued by webui
}

// enrollResponse is the JSON body returned on successful enrollment.
type enrollResponse struct {
	Cert      string `json:"cert"`       // PEM client cert
	CAChain   string `json:"ca_chain"`   // PEM org CA (root chain for validation)
	ExpiresAt string `json:"expires_at"` // RFC3339
}

var enrollTokensMu sync.Mutex // protects on-disk token file ops

// loadEnrollConfig reads env vars and CA files. If the org CA cannot be
// parsed, returns an error so main can decide whether enrollment should be
// disabled or the process should exit.
func loadEnrollConfig() (*enrollConfig, error) {
	tokensFile := getEnv("ENROLL_TOKENS_FILE", "/config/enroll-tokens.json")
	devicesFile := getEnv("DEVICES_FILE", "/config/devices.json")
	cfg := &enrollConfig{
		Listen:          getEnv("ENROLL_LISTEN", ":3131"),
		TokensFile:      tokensFile,
		TokensLockFile:  getEnv("ENROLL_TOKENS_LOCK_FILE", tokensFile+".lock"),
		DevicesFile:     devicesFile,
		DevicesLockFile: devicesFile + ".lock",
		LockTimeout:     5 * time.Second,
		CertLifetime:    7 * 24 * time.Hour,
	}
	caCertFile := getEnv("ORG_CA_FILE", "/config/org-ca.pem")
	caKeyFile := getEnv("ORG_CA_KEY_FILE", "/config/org-ca.key")

	cert, key, pemBytes, err := loadOrgCA(caCertFile, caKeyFile)
	if err != nil {
		return nil, err
	}
	cfg.OrgCACert = cert
	cfg.OrgCAKey = key
	cfg.OrgCAPEM = pemBytes
	return cfg, nil
}

func loadOrgCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read ORG_CA_FILE %s: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read ORG_CA_KEY_FILE %s: %w", keyFile, err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, nil, fmt.Errorf("ORG_CA_FILE %s: no PEM block", certFile)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse org CA cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, nil, fmt.Errorf("ORG_CA_KEY_FILE %s: no PEM block", keyFile)
	}
	var key *rsa.PrivateKey
	switch kb.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse org CA key (PKCS1): %w", err)
		}
	case "PRIVATE KEY":
		raw, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse org CA key (PKCS8): %w", err)
		}
		var ok bool
		key, ok = raw.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, nil, fmt.Errorf("org CA key is not RSA (got %T)", raw)
		}
	default:
		return nil, nil, nil, fmt.Errorf("unsupported org CA key PEM type: %s", kb.Type)
	}
	return cert, key, certPEM, nil
}

// startEnrollServer mounts the /enroll handler on cfg.Listen.
func startEnrollServer(cfg *enrollConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		handleEnroll(cfg, w, r)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		log.Printf("[tls-proxy] enroll endpoint on %s (ORG_CA loaded, lifetime=%s)", cfg.Listen, cfg.CertLifetime)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[tls-proxy] enroll server: %v", err)
		}
	}()
	return nil
}

func handleEnroll(cfg *enrollConfig, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req enrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.CSR) == "" || strings.TrimSpace(req.EnrollmentToken) == "" {
		http.Error(w, "missing csr or enrollment_token", http.StatusBadRequest)
		return
	}

	csr, err := parseCSRPEM(req.CSR)
	if err != nil {
		http.Error(w, "invalid csr: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "csr signature invalid: "+err.Error(), http.StatusBadRequest)
		return
	}

	tok, err := consumeEnrollToken(cfg, req.EnrollmentToken)
	if err != nil {
		// flock contention is transient: ask the client to retry.
		if errors.Is(err, ErrFlockTimeout) {
			log.Printf("[tls-proxy] enroll lock timeout (remote=%s)", r.RemoteAddr)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "token store busy; retry shortly", http.StatusServiceUnavailable)
			return
		}
		log.Printf("[tls-proxy] enroll token rejected: %v (remote=%s)", err, r.RemoteAddr)
		http.Error(w, "enrollment_token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Force the issued cert's Subject to the values bound to the token,
	// preventing a client from claiming an arbitrary identity in the CSR.
	subject := pkix.Name{
		CommonName:   pickCommonName(tok, csr),
		Organization: []string{tok.OrgID},
	}

	certPEM, expiresAt, serial, err := signCSR(cfg, csr, subject)
	if err != nil {
		log.Printf("[tls-proxy] sign CSR: %v", err)
		http.Error(w, "sign error", http.StatusInternalServerError)
		return
	}

	// Persist the device record so the webui can later revoke it. The CRL
	// path (/config/revoked-serials.json) is webui-driven and keys off
	// SerialHex, so we must populate that field. Format must match
	// normalizeSerialHex's canonical lowercase-no-separator form.
	serialHex := normalizeSerialHex(serial.Text(16))
	if err := persistDevice(cfg, subject, tok, serialHex, expiresAt); err != nil {
		// We have already signed and consumed the token; failing here
		// would leave the client without a usable record. Log loudly but
		// still return the cert — the admin can manually reconcile.
		// However if this turns out to be flock contention we can at
		// least surface 503 so the caller retries before the cert leaves
		// the server.
		if errors.Is(err, ErrFlockTimeout) {
			log.Printf("[tls-proxy] devices lock timeout (cn=%s) — returning 503", subject.CommonName)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "device store busy; retry shortly", http.StatusServiceUnavailable)
			return
		}
		log.Printf("[tls-proxy] device persist FAILED (cn=%s serial=%s): %v — cert was issued; manual reconciliation required",
			subject.CommonName, serialHex, err)
		// Fall through and still return the cert; the CRL path will be
		// non-functional for this device until an admin re-adds it.
	}

	resp := enrollResponse{
		Cert:      string(certPEM),
		CAChain:   string(cfg.OrgCAPEM),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)

	log.Printf("[tls-proxy] enrollment success: cn=%s org=%s serial=%s expires=%s",
		subject.CommonName, tok.OrgID, serialHex, resp.ExpiresAt)
}

// persistDevice writes a new device record into devices.json under flock.
// Caller has already signed the cert, so any error here leaves the cert
// issued but unrevocable from the WebUI; surface flock-timeout as a
// retryable 503, log everything else for manual reconciliation.
func persistDevice(cfg *enrollConfig, subject pkix.Name, tok enrollToken, serialHex string, expiresAt time.Time) error {
	if cfg.DevicesFile == "" {
		// Nothing to write to. (Tests can intentionally leave this blank.)
		return nil
	}
	deviceID, err := newDeviceID()
	if err != nil {
		return fmt.Errorf("device id: %w", err)
	}
	d := device{
		DeviceID:  deviceID,
		Subject:   subject.CommonName,
		Org:       tok.OrgID,
		SerialHex: serialHex,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: expiresAt.UTC(),
		Revoked:   false,
	}
	return appendDevice(cfg.DevicesFile, cfg.DevicesLockFile, cfg.LockTimeout, d)
}

func pickCommonName(tok enrollToken, csr *x509.CertificateRequest) string {
	// Prefer token-bound user; if the token did not specify one, fall back
	// to the CSR's CN. This lets an admin pre-allocate a token to "anyone"
	// while still letting the client tag their hostname.
	if tok.User != "" {
		return tok.User
	}
	cn := strings.TrimSpace(csr.Subject.CommonName)
	if cn == "" {
		return "unknown@unknown"
	}
	return cn
}

func parseCSRPEM(s string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// signCSR issues a client cert with the given Subject, signed by the org CA.
// Returns the PEM-encoded cert, the not-after timestamp, and the serial
// (as *big.Int) so the caller can also persist the serial in canonical
// form via normalizeSerialHex(serial.Text(16)).
func signCSR(cfg *enrollConfig, csr *x509.CertificateRequest, subject pkix.Name) ([]byte, time.Time, *big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	now := time.Now().UTC()
	notAfter := now.Add(cfg.CertLifetime)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, cfg.OrgCACert, csr.PublicKey, cfg.OrgCAKey)
	if err != nil {
		return nil, time.Time{}, nil, fmt.Errorf("create cert: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, notAfter, serial, nil
}

// consumeEnrollToken atomically validates a token and marks it consumed.
// Returns the matched record on success.
//
// Concurrency: protected by two layers.
//   1. In-process mutex (enrollTokensMu) — serialises within tls-proxy.
//   2. OS-level flock on cfg.TokensLockFile — serialises with the webui
//      process which writes the same file when issuing/revoking tokens.
//
// If the OS lock cannot be acquired within cfg.LockTimeout the function
// returns ErrFlockTimeout (caller surfaces 503).
func consumeEnrollToken(cfg *enrollConfig, token string) (enrollToken, error) {
	enrollTokensMu.Lock()
	defer enrollTokensMu.Unlock()

	var matched enrollToken
	err := WithFlock(cfg.TokensLockFile, cfg.LockTimeout, func() error {
		store, err := readTokenStore(cfg.TokensFile)
		if err != nil {
			return fmt.Errorf("read tokens: %w", err)
		}
		now := time.Now().UTC()
		for i := range store.Tokens {
			t := &store.Tokens[i]
			if t.Token != token {
				continue
			}
			if !t.ConsumedAt.IsZero() {
				return errors.New("already consumed")
			}
			if !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt) {
				return errors.New("expired")
			}
			t.ConsumedAt = now
			t.UsedCount++
			if err := writeTokenStore(cfg.TokensFile, store); err != nil {
				return fmt.Errorf("persist tokens: %w", err)
			}
			matched = *t
			return nil
		}
		return errors.New("not found")
	})
	if err != nil {
		return enrollToken{}, err
	}
	return matched, nil
}

func readTokenStore(path string) (*enrollTokenStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &enrollTokenStore{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return &enrollTokenStore{}, nil
	}
	var store enrollTokenStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	return &store, nil
}

func writeTokenStore(path string, store *enrollTokenStore) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
