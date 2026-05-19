// Package proxy implements the local HTTP CONNECT forwarding proxy.
//
// AI clients are configured (via HTTPS_PROXY) to point at 127.0.0.1:8443.
// This package terminates that HTTP CONNECT, then opens an mTLS tunnel to
// the org Interceptor, splicing bytes in both directions.
//
// Phase 1 scope:
//   - HTTP CONNECT only (no plain HTTP forwarding)
//   - graceful shutdown via context
//   - fail_close vs. fail_open fallback
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ai-scan-connect/config"
)

// Forwarder is a local HTTP CONNECT proxy that tunnels to the Interceptor over mTLS.
type Forwarder struct {
	// ListenAddr e.g. "127.0.0.1:8443".
	ListenAddr string

	// InterceptorHostPort is the upstream Interceptor's host:port.
	InterceptorHostPort string

	// ClientCert is the mTLS client cert (key+cert).
	ClientCert tls.Certificate

	// RootCAs is the trust pool for verifying the Interceptor's server cert.
	RootCAs *x509.CertPool

	// FailClose: when true, return 503 if upstream mTLS fails.
	// When false, fall back to direct origin connect.
	FailClose bool

	// Logger for runtime diagnostics. nil -> log.Default().
	Logger *log.Logger

	listener net.Listener
}

// NewFromConfig builds a Forwarder from the loaded config + cert paths.
// If certPath/keyPath is empty or files are missing, a Forwarder with no
// client cert is returned (callers may still test/start it; mTLS will fail
// upstream and engage the FailClose policy).
func NewFromConfig(cfg *config.Config, certPath, keyPath string) (*Forwarder, error) {
	hostPort, err := hostPortFromURL(cfg.InterceptorURL)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.OrgCAPEM)) {
		return nil, errors.New("forwarder: invalid org_ca_pem")
	}

	f := &Forwarder{
		ListenAddr:          cfg.LocalListen,
		InterceptorHostPort: hostPort,
		RootCAs:             pool,
		FailClose:           cfg.FailClose,
	}

	if certPath != "" && keyPath != "" {
		if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			f.ClientCert = cert
		} else {
			// Caller decides whether this is fatal — surface as warning via logger.
			log.Printf("forwarder: client cert not loaded (%v); upstream mTLS will fail", err)
		}
	}
	return f, nil
}

func hostPortFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("forwarder: parse %s: %w", raw, err)
	}
	host := u.Host
	if host == "" {
		return "", fmt.Errorf("forwarder: no host in %s", raw)
	}
	if !strings.Contains(host, ":") {
		// Default to 3128 (tls-proxy mTLS listener) if no port given.
		host = host + ":3128"
	}
	return host, nil
}

func (f *Forwarder) logger() *log.Logger {
	if f.Logger != nil {
		return f.Logger
	}
	return log.Default()
}

// ListenAndServe binds and serves until ctx is cancelled.
func (f *Forwarder) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", f.ListenAddr)
	if err != nil {
		return fmt.Errorf("forwarder: listen %s: %w", f.ListenAddr, err)
	}
	f.listener = ln
	f.logger().Printf("forwarder: listening on %s, upstream=%s fail_close=%v",
		f.ListenAddr, f.InterceptorHostPort, f.FailClose)

	// Cancellation -> close listener to unblock Accept.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			f.logger().Printf("forwarder: accept: %v", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.handle(ctx, conn)
		}()
	}
}

// Addr returns the bound address (only valid after ListenAndServe has bound).
func (f *Forwarder) Addr() net.Addr {
	if f.listener == nil {
		return nil
	}
	return f.listener.Addr()
}

func (f *Forwarder) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	if req.Method != http.MethodConnect {
		// Phase 1: only CONNECT supported.
		writeStatus(c, http.StatusMethodNotAllowed, "only CONNECT supported")
		return
	}
	target := req.Host // "host:port"
	f.logger().Printf("forwarder: CONNECT %s", target)

	upstream, err := f.dialUpstream(ctx, target)
	if err != nil {
		f.logger().Printf("forwarder: dial upstream failed: %v", err)
		if f.FailClose {
			writeStatus(c, http.StatusServiceUnavailable, "upstream unavailable")
			return
		}
		// Fail-open: connect directly to origin.
		direct, derr := net.DialTimeout("tcp", target, 10*time.Second)
		if derr != nil {
			writeStatus(c, http.StatusBadGateway, "direct dial failed")
			return
		}
		upstream = direct
	}
	defer upstream.Close()

	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	splice(c, upstream)
}

func writeStatus(w io.Writer, code int, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		code, http.StatusText(code))
	_ = msg // (msg is intentionally not echoed back to limit info leaks)
}

// dialUpstream opens a single mTLS connection to the Interceptor and sends
// an inner HTTP CONNECT for the requested target. The Interceptor's tls-proxy
// is responsible for splitting Anthropic vs. other traffic.
//
// Phase 1 simplification: we just dial the upstream over mTLS and forward the
// caller's CONNECT verbatim. (Real impl will likely re-issue CONNECT with
// rewritten headers.)
func (f *Forwarder) dialUpstream(ctx context.Context, target string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tcp, err := dialer.DialContext(ctx, "tcp", f.InterceptorHostPort)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		RootCAs:    f.RootCAs,
		MinVersion: tls.VersionTLS12,
		ServerName: serverNameOf(f.InterceptorHostPort),
	}
	if f.ClientCert.Certificate != nil {
		tlsCfg.Certificates = []tls.Certificate{f.ClientCert}
	}

	conn := tls.Client(tcp, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("mTLS handshake: %w", err)
	}

	// Issue inner CONNECT to the Interceptor for the original target.
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ai-scan-connect/0.1\r\n\r\n",
		target, target)
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream CONNECT %s returned %d", target, resp.StatusCode)
	}
	return conn, nil
}

func serverNameOf(hostPort string) string {
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return h
}

func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); _ = a.SetReadDeadline(time.Now()) }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); _ = b.SetReadDeadline(time.Now()) }()
	wg.Wait()
}
