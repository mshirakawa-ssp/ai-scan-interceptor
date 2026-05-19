// tls-proxy: HTTPS forward proxy that impersonates a Chrome TLS fingerprint
// for configured target domains. Terminates TLS from the client using the
// shared CA cert, inspects the request body, then re-dials the origin with
// utls (Chrome fingerprint) so Cloudflare bot-protection does not trigger.
// All other CONNECT/HTTP traffic is forwarded transparently to an upstream proxy.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ai-scan-interceptor/detection"
	"ai-scan-interceptor/notification"
	"ai-scan-interceptor/policy"
	"ai-scan-interceptor/storage"

	utls "github.com/refraction-networking/utls"
)

// --- Configuration via environment variables ---

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvSlice(key string, fallback []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// interceptHosts: CONNECT to these hosts is terminated and inspected locally.
// Everything else goes to upstream. Override with INTERCEPT_HOSTS env var.
var defaultInterceptHosts = []string{
	"api.anthropic.com",
	"a-api.anthropic.com",
	"claude.ai",
}

// --- Globals ---

var (
	listenAddr    string
	upstreamProxy string
	interceptSet  map[string]bool

	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
	certCache    = &syncCertCache{m: make(map[string]*certEntry)}
	detector     *detection.Detector
	logger       *storage.Logger
	policyConfig *policy.Config
	notifier     *notification.Notifier
)

// connWithReader wraps a net.Conn so that Reads first drain an io.Reader
// (typically a bufio.Reader that already buffered some bytes) before falling
// through to the underlying connection.
type connWithReader struct {
	net.Conn
	r io.Reader
}

func (c *connWithReader) Read(b []byte) (int, error) { return c.r.Read(b) }

// --- Certificate cache ---

type certEntry struct {
	cert tls.Certificate
	exp  time.Time
}

type syncCertCache struct {
	mu sync.Mutex
	m  map[string]*certEntry
}

func (c *syncCertCache) get(host string) (tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[host]; ok && time.Now().Before(e.exp) {
		return e.cert, nil
	}
	cert, err := issueCert(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	c.m[host] = &certEntry{cert: cert, exp: time.Now().Add(12 * time.Hour)}
	return cert, nil
}

func issueCert(host string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// --- Main ---

func main() {
	listenAddr = getEnv("PROXY_ADDR", ":3128")
	upstreamProxy = getEnv("UPSTREAM_PROXY", "squid:3129")
	logDir := getEnv("LOG_DIR", "/logs")
	configDir := getEnv("CONFIG_DIR", "/config")
	caCertFile := getEnv("CA_CERT", "/ca/squid-ca.pem")
	caKeyFile := getEnv("CA_KEY", "/ca/squid-ca.key")

	// Build intercept host set
	hosts := getEnvSlice("INTERCEPT_HOSTS", defaultInterceptHosts)
	interceptSet = make(map[string]bool, len(hosts))
	for _, h := range hosts {
		interceptSet[strings.ToLower(h)] = true
	}

	if err := loadCA(caCertFile, caKeyFile); err != nil {
		log.Fatalf("[tls-proxy] CA load error: %v", err)
	}
	log.Printf("[tls-proxy] CA loaded: %s", caCertFile)

	var err error
	logger, err = storage.NewLogger(logDir)
	if err != nil {
		log.Fatalf("[tls-proxy] logger: %v", err)
	}
	defer logger.Close()

	// --- Policy config ---
	policyConfig, err = policy.Load(configDir + "/policy.json")
	if err != nil {
		log.Fatalf("[tls-proxy] policy load: %v", err)
	}
	policyConfig.StartReloader()
	log.Printf("[tls-proxy] policy loaded: mode=%s", policyConfig.Get().GlobalMode)

	notifStore := notification.LoadConfigStore(configDir + "/notification.json")
	notifier = notification.NewDynamicNotifier(notifStore, notification.EmailConfig{
		Host:     getEnv("SMTP_HOST", ""),
		Port:     getEnv("SMTP_PORT", "587"),
		User:     getEnv("SMTP_USER", ""),
		Password: getEnv("SMTP_PASS", ""),
		From:     getEnv("SMTP_FROM", ""),
		To:       getEnvSlice("ALERT_EMAIL_TO", nil),
	}, getEnv("WEBHOOK_URL", ""))

	detector = detection.NewDetector()

	// --- Unified rules store (same pattern as icap-server) ---
	rulesPath := configDir + "/rules.json"
	if err := detection.SeedRulesFile(rulesPath); err != nil {
		log.Printf("[tls-proxy] rules seed warning: %v", err)
	}
	ruleEntries, err := detection.LoadRulesFile(rulesPath)
	if err != nil {
		log.Printf("[tls-proxy] rules load warning: %v, using built-in defaults", err)
		ruleEntries = detection.DefaultEntries()
	}
	detection.SetActiveRules(detection.EntriesToAlertRules(ruleEntries))
	detection.StartRulesReloader(rulesPath)
	log.Printf("[tls-proxy] loaded %d rules", len(detection.ActiveRules()))

	log.Printf("[tls-proxy] listening on %s", listenAddr)
	log.Printf("[tls-proxy] upstream proxy: %s", upstreamProxy)
	log.Printf("[tls-proxy] intercept hosts: %v", hosts)

	// --- Optional: mTLS inbound listener for AI-Scan-Connect clients. ---
	// Disabled by default. Activated when MTLS_ENABLED=true and an org CA
	// is present at ORG_CA_FILE. See mtls.go for full behaviour.
	if mtlsCfg, mErr := loadMTLSConfig(); mErr != nil {
		log.Fatalf("[tls-proxy] mtls config: %v", mErr)
	} else if mtlsCfg != nil {
		// Load the revocation list (CRL). File-missing is non-fatal —
		// we treat it as an empty set so the system stays available
		// before the webui has written its first record.
		crlPath := getEnv("CRL_FILE", "/config/revoked-serials.json")
		revoked, rErr := LoadRevokedStore(crlPath)
		if rErr != nil {
			log.Fatalf("[tls-proxy] CRL load %s: %v", crlPath, rErr)
		}
		log.Printf("[tls-proxy] CRL loaded from %s (%d revoked entries)", crlPath, revoked.Size())
		revoked.StartReloader(context.Background(), crlPath, 30*time.Second)
		mtlsCfg.Revoked = revoked

		if err := startMTLSListener(mtlsCfg); err != nil {
			log.Fatalf("[tls-proxy] mtls listener: %v", err)
		}
		// Enrollment endpoint only makes sense alongside mTLS.
		if eCfg, eErr := loadEnrollConfig(); eErr != nil {
			log.Fatalf("[tls-proxy] enroll config: %v", eErr)
		} else if err := startEnrollServer(eCfg); err != nil {
			log.Fatalf("[tls-proxy] enroll listener: %v", err)
		}
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("[tls-proxy] listen: %v", err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[tls-proxy] accept error: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

// --- Connection handler ---

func handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect {
		forwardPlainHTTP(conn, req)
		return
	}

	host := bareHost(req.Host)
	proxyAuth := req.Header.Get("Proxy-Authorization")
	proxyUser := extractProxyUser(proxyAuth)
	if interceptSet[strings.ToLower(host)] {
		interceptTLS(conn, br, req.Host, proxyUser)
	} else {
		// Forward Proxy-Authorization to Squid so it can authenticate the user
		// and pass the username to ICAP via X-Client-Username.
		tunnelToUpstream(conn, br, req.Host, proxyAuth)
	}
}

// interceptTLS: TLS-terminate the client, inspect each request body, forward
// to origin using Go's net/http transport (handles HTTP/2 transparently) with
// a Chrome utls ClientHello so Cloudflare bot-protection does not trigger.
func interceptTLS(rawConn net.Conn, clientBuf *bufio.Reader, hostPort string, proxyUser string) {
	host := bareHost(hostPort)

	// Resolve client identity once per connection.
	// Priority: mTLS peer cert > reverse-DNS hostname > proxy Basic-auth username.
	var (
		clientUserID   string
		identitySource string
	)
	if id := peerIdentityFromConn(rawConn); id.HasUser() {
		clientUserID = id.UserHost
		identitySource = "mtls-cert"
	}
	if clientUserID == "" {
		if h := lookupHostname(rawConn.RemoteAddr().String()); h != "" {
			clientUserID = h
			identitySource = "reverse-dns"
		}
	}
	if clientUserID == "" && proxyUser != "" {
		clientUserID = proxyUser
		// proxy basic auth is not in the canonical IdentitySource enum
		// agreed with icap-server; leave identitySource empty so it falls
		// through to the "ip-only" semantics on the consumer side.
	}
	if identitySource == "" && clientUserID == "" {
		identitySource = "ip-only"
	}

	// ACK the CONNECT
	fmt.Fprint(rawConn, "HTTP/1.1 200 Connection established\r\n\r\n")

	// TLS-terminate the client.
	// Wrap rawConn with clientBuf so that bytes already buffered by the CONNECT
	// request reader-ahead are not lost during the subsequent TLS handshake.
	cert, err := certCache.get(host)
	if err != nil {
		log.Printf("[tls-proxy] cert error %s: %v", host, err)
		return
	}
	tlsConn := &connWithReader{Conn: rawConn, r: io.MultiReader(clientBuf, rawConn)}
	clientTLS := tls.Server(tlsConn, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("[tls-proxy] TLS handshake failed for %s (CA not trusted?): %v — falling back to upstream tunnel", host, err)
		clientTLS.Close()
		tunnelToUpstreamRaw(rawConn, hostPort)
		return
	}
	defer clientTLS.Close()

	// chromeDial forces HTTP/1.1 ALPN so origins always speak HTTP/1.1.
	// http.Transport handles the connection pooling; it reads NegotiatedProtocol
	// from the utls ConnectionState to confirm the protocol.
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return chromeDial(addr)
		},
	}
	defer transport.CloseIdleConnections()

	// Handle keep-alive: loop over requests on this TLS connection.
	httpBuf := bufio.NewReader(clientTLS)
	for {
		httpReq, err := http.ReadRequest(httpBuf)
		if err != nil {
			return
		}

		body, err := io.ReadAll(httpReq.Body)
		httpReq.Body.Close()
		if err != nil {
			return
		}

		result, entry, matched := inspectRequest(host, httpReq.URL.Path, httpReq.Method, body, clientUserID, identitySource, rawConn.RemoteAddr().String())

		// Apply policy if a prompt was detected.
		if matched && result != nil && entry != nil {
			mode := policy.ModeWarn
			if policyConfig != nil {
				mode = policyConfig.GetMode(result.Service)
			}

			// File uploads cannot be safely masked (reconstructed multipart bodies are
			// rejected by upstream servers, causing the original to be retried unmasked).
			// Escalate mask→block for file upload requests when credentials are triggered.
			effectiveMode := mode
			if result.IsFileUpload && result.Triggered && mode == policy.ModeMask {
				effectiveMode = policy.ModeBlock
				log.Printf("[tls-proxy] file upload with sensitive content: escalating mask→block service=%s", result.Service)
			}

			// Determine action based on trigger state and enforcement mode.
			if !result.Triggered {
				entry.Action = "passed"
			} else {
				switch effectiveMode {
				case policy.ModeBlock:
					entry.Action = "blocked"
				case policy.ModeMask:
					entry.Action = "masked"
				case policy.ModeMonitor:
					entry.Action = "monitored"
				default:
					entry.Action = "warned"
				}
			}

			if err := logger.Write(*entry); err != nil {
				log.Printf("[tls-proxy] log write error: %v", err)
			}

			if result.Triggered {
				switch effectiveMode {
				case policy.ModeBlock:
					log.Printf("[tls-proxy] blocking request: service=%s isFileUpload=%v", result.Service, result.IsFileUpload)
					fmt.Fprint(clientTLS, "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 51\r\n\r\n{\"error\":\"Request blocked by AI governance policy\"}")
					return
				case policy.ModeMask:
					before := len(body)
					body = detection.MaskSensitiveForService(body, host, httpReq.URL.Path)
					log.Printf("[tls-proxy] masking done: service=%s before=%d after=%d changed=%v",
						result.Service, before, len(body), len(body) != before)
				case policy.ModeMonitor:
					// Log only, no further action needed — fall through to forward.
				default: // ModeWarn
					notifier.Send(entry)
				}
			}
		}

		// Build the outbound request.
		outURL := "https://" + host + httpReq.URL.RequestURI()
		outReq, err := http.NewRequestWithContext(context.Background(), httpReq.Method, outURL, bytes.NewReader(body))
		if err != nil {
			fmt.Fprint(clientTLS, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		outReq.Header = httpReq.Header.Clone()
		outReq.ContentLength = int64(len(body))

		resp, err := transport.RoundTrip(outReq)
		if err != nil {
			log.Printf("[tls-proxy] round trip %s: %v", host, err)
			fmt.Fprint(clientTLS, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}

		writeErr := resp.Write(clientTLS)
		resp.Body.Close()
		if writeErr != nil {
			return
		}
		if resp.Close || httpReq.Close {
			return
		}
	}
}

// chromeDial connects to host using a Chrome-impersonating TLS ClientHello.
// ALPN is forced to HTTP/1.1 so Cloudflare cannot fingerprint the HTTP/2
// SETTINGS frame (Go's h2 SETTINGS differ from Chrome's). JA3 is unaffected
// because it hashes extension type (16) but not the ALPN protocol values.
func chromeDial(hostPort string) (net.Conn, error) {
	if !strings.Contains(hostPort, ":") {
		hostPort = hostPort + ":443"
	}
	host := bareHost(hostPort)

	tcp, err := net.DialTimeout("tcp", hostPort, 15*time.Second)
	if err != nil {
		return nil, err
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("utls spec: %w", err)
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			break
		}
	}

	uc := utls.UClient(tcp, &utls.Config{ServerName: host}, utls.HelloCustom)
	if err := uc.ApplyPreset(&spec); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("utls preset: %w", err)
	}
	if err := uc.Handshake(); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("utls: %w", err)
	}
	return uc, nil
}

// tunnelToUpstream: relay CONNECT through the upstream proxy.
// proxyAuth is the original Proxy-Authorization header value from the client;
// it is forwarded to Squid so Squid can authenticate the user and pass the
// username to the ICAP server via X-Client-Username.
func tunnelToUpstream(clientConn net.Conn, clientBuf *bufio.Reader, hostPort string, proxyAuth string) {
	up, err := net.DialTimeout("tcp", upstreamProxy, 10*time.Second)
	if err != nil {
		log.Printf("[tls-proxy] upstream dial: %v", err)
		fmt.Fprint(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()

	connectHdr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n", hostPort, hostPort)
	if proxyAuth != "" {
		connectHdr += "Proxy-Authorization: " + proxyAuth + "\r\n"
	}
	connectHdr += "\r\n"
	fmt.Fprint(up, connectHdr)
	upBuf := bufio.NewReader(up)
	resp, err := http.ReadResponse(upBuf, nil)
	if err != nil || resp.StatusCode != 200 {
		code := 502
		if resp != nil {
			code = resp.StatusCode
		}
		fmt.Fprintf(clientConn, "HTTP/1.1 %d Bad Gateway\r\n\r\n", code)
		return
	}

	fmt.Fprint(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n")
	pipe(clientConn, up, clientBuf)
}

// tunnelToUpstreamRaw: used for TLS handshake fallback — the client already
// received a 200 but TLS failed. Re-establish a raw tunnel via upstream.
// This handles the case where the client's CA store does not trust our cert.
func tunnelToUpstreamRaw(clientConn net.Conn, hostPort string) {
	up, err := net.DialTimeout("tcp", upstreamProxy, 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", hostPort, hostPort)
	upBuf := bufio.NewReader(up)
	resp, err := http.ReadResponse(upBuf, nil)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	pipe(clientConn, up, nil)
}

// forwardPlainHTTP: plain HTTP (non-CONNECT) → upstream proxy.
func forwardPlainHTTP(clientConn net.Conn, req *http.Request) {
	up, err := net.DialTimeout("tcp", upstreamProxy, 10*time.Second)
	if err != nil {
		fmt.Fprint(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	req.Write(up)
	upBuf := bufio.NewReader(up)
	resp, err := http.ReadResponse(upBuf, req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	resp.Write(clientConn)
}

// pipe: bidirectional copy between two connections.
// If extraBuf is non-nil its buffered bytes are flushed to b before piping.
func pipe(a net.Conn, b net.Conn, extraBuf *bufio.Reader) {
	done := make(chan struct{}, 2)
	var srcA io.Reader = a
	if extraBuf != nil {
		srcA = io.MultiReader(extraBuf, a)
	}
	go func() { io.Copy(b, srcA); done <- struct{}{} }()
	go func() { io.Copy(a, b); done <- struct{}{} }()
	<-done
}

// --- Prompt inspection ---

// inspectRequest detects AI prompts in the request body and builds a log entry.
// It returns the detection Result, the partially-filled LogEntry (Action not yet set),
// and whether a match was found. The caller is responsible for setting entry.Action
// and writing the entry to the log.
func inspectRequest(host, path, method string, body []byte, userID, identitySource, clientAddr string) (*detection.Result, *storage.LogEntry, bool) {
	if len(body) == 0 {
		return nil, nil, false
	}
	result, matched := detector.Detect(host, path, method, body)
	if !matched {
		return nil, nil, false
	}

	var ruleIDs []string
	for _, rm := range result.RuleMatches {
		ruleIDs = append(ruleIDs, rm.RuleID+":"+rm.Description)
	}
	entry := &storage.LogEntry{
		Timestamp:      time.Now().UTC(),
		Service:        result.Service,
		Host:           host,
		Path:           path,
		Prompt:         result.Prompt,
		Triggered:      result.Triggered,
		Severity:       result.Severity,
		RuleIDs:        ruleIDs,
		ClientIP:       clientAddr,
		UserID:         userID,
		IdentitySource: identitySource,
	}

	if result.Triggered {
		log.Printf("[tls-proxy] ALERT service=%s sev=%s prompt=%q",
			result.Service, result.Severity, trunc(result.Prompt, 80))
	} else {
		log.Printf("[tls-proxy] captured service=%s prompt=%q", result.Service, trunc(result.Prompt, 80))
	}
	return result, entry, true
}

// --- CA loading ---

func loadCA(certFile, keyFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("invalid cert PEM")
	}
	caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("invalid key PEM")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse key (PKCS1): %w", err)
		}
	case "PRIVATE KEY":
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return fmt.Errorf("parse key (PKCS8): %w", err2)
		}
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("key is not RSA (type: %T)", key)
		}
	default:
		return fmt.Errorf("unsupported key PEM type: %s", block.Type)
	}
	return nil
}

// --- Utilities ---

func bareHost(hostPort string) string {
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return h
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// hostnameCache caches reverse-DNS results to avoid repeated lookups per connection.
var (
	hostnameCacheMu sync.Mutex
	hostnameCache   = map[string]hostnameCacheEntry{}
)

type hostnameCacheEntry struct {
	name    string
	expires time.Time
}

// lookupHostname resolves a client IP to its short hostname (first DNS label).
// Returns "" if the lookup fails or the address is loopback/local.
func lookupHostname(addr string) string {
	ip := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		ip = h
	}
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return ""
	}

	hostnameCacheMu.Lock()
	if e, ok := hostnameCache[ip]; ok && time.Now().Before(e.expires) {
		hostnameCacheMu.Unlock()
		return e.name
	}
	hostnameCacheMu.Unlock()

	name := ""
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		// Trim trailing dot; keep only the short hostname (first label).
		fqdn := strings.TrimSuffix(names[0], ".")
		if idx := strings.IndexByte(fqdn, '.'); idx > 0 {
			name = fqdn[:idx]
		} else {
			name = fqdn
		}
		// Docker container names are infrastructure, not user identities.
		if strings.Contains(name, "ai-scan-interceptor-") {
			name = ""
		}
	}

	hostnameCacheMu.Lock()
	hostnameCache[ip] = hostnameCacheEntry{name: name, expires: time.Now().Add(5 * time.Minute)}
	hostnameCacheMu.Unlock()
	return name
}

// extractProxyUser decodes a Proxy-Authorization: Basic header and returns the username.
func extractProxyUser(authHeader string) string {
	creds, ok := strings.CutPrefix(authHeader, "Basic ")
	if !ok {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(creds)
	if err != nil {
		return ""
	}
	user, _, _ := strings.Cut(string(decoded), ":")
	return user
}

// jwtSub parses the sub claim from a Bearer JWT without verifying the signature.
func jwtSub(authHeader string) string {
	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok || token == "" {
		return ""
	}
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Sub
}
