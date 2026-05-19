// mtls.go: optional mTLS inbound listener for AI-Scan-Connect clients.
//
// Behaviour:
//   - Disabled by default. Enabled only when MTLS_ENABLED=true.
//   - Listens on MTLS_PORT (default :3130) with TLS termination, requiring
//     a valid client certificate signed by ORG_CA_FILE (default
//     /config/org-ca.pem).
//   - After mTLS handshake, the inner stream is the same HTTP/CONNECT
//     proxy protocol the existing :3128 listener speaks, so the same
//     handleConn logic applies.
//   - Peer identity (CN=user@host, O=org) is attached to the connection
//     via identityConn and surfaced in LogEntry.UserID / IdentitySource.
//
// This is purely additive: when MTLS_ENABLED is unset or false, this file
// contributes nothing at runtime and the existing :3128 path is unchanged.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

// identityConn is a net.Conn wrapper that carries a verified mTLS peer
// identity. handleConn type-asserts to retrieve it.
type identityConn struct {
	net.Conn
	identity PeerIdentity
}

// peerIdentityFromConn walks any wrapper layers (identityConn, connWithReader)
// to find the underlying mTLS peer identity. Returns zero PeerIdentity if
// none is present.
func peerIdentityFromConn(c net.Conn) PeerIdentity {
	for {
		switch v := c.(type) {
		case *identityConn:
			return v.identity
		case *connWithReader:
			c = v.Conn
		default:
			return PeerIdentity{}
		}
	}
}

// mtlsConfig holds parsed mTLS settings.
type mtlsConfig struct {
	Enabled  bool
	Listen   string
	OrgCAPEM []byte
	OrgCAs   *x509.CertPool
	// ServerCert is the cert presented to clients during the inbound TLS
	// handshake. We reuse the existing forged-server CA (caCert/caKey) by
	// minting a long-lived "proxy-mtls" leaf at startup. This is acceptable
	// because clients pin the org-CA only for *client* auth; for server
	// auth they trust the same CA they already trust to MITM other hosts.
	ServerCert tls.Certificate
	// Revoked, when non-nil, is consulted during the TLS handshake to
	// reject revoked client certs. May be nil (treated as "no revocations").
	Revoked *RevokedStore
}

// loadMTLSConfig reads env vars and CA file. Returns (nil, nil) when
// MTLS_ENABLED is not "true" so the caller can simply skip startup.
func loadMTLSConfig() (*mtlsConfig, error) {
	if strings.ToLower(strings.TrimSpace(os.Getenv("MTLS_ENABLED"))) != "true" {
		return nil, nil
	}
	cfg := &mtlsConfig{
		Enabled: true,
		Listen:  getEnv("MTLS_PORT", ":3130"),
	}

	orgCAFile := getEnv("ORG_CA_FILE", "/config/org-ca.pem")
	pemBytes, err := os.ReadFile(orgCAFile)
	if err != nil {
		return nil, fmt.Errorf("read ORG_CA_FILE %s: %w", orgCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("ORG_CA_FILE %s: no valid PEM CA certs found", orgCAFile)
	}
	cfg.OrgCAPEM = pemBytes
	cfg.OrgCAs = pool

	// Re-use the existing forged-server CA to mint a server cert for the
	// mTLS listener. caCert/caKey are populated by loadCA() in main.
	if caCert == nil || caKey == nil {
		return nil, errors.New("server CA not loaded; call loadCA before loadMTLSConfig")
	}
	host, _ := splitHostNoErr(cfg.Listen)
	if host == "" {
		host = "ai-scan-interceptor"
	}
	srvCert, err := mintServerCertForMTLS(host)
	if err != nil {
		return nil, fmt.Errorf("mint mTLS server cert: %w", err)
	}
	cfg.ServerCert = srvCert
	return cfg, nil
}

// mintServerCertForMTLS issues a server cert for the inbound mTLS listener
// signed by the existing CA. Cached so we only mint once per process.
var (
	mtlsServerCertOnce sync.Once
	mtlsServerCert     tls.Certificate
	mtlsServerCertErr  error
)

func mintServerCertForMTLS(host string) (tls.Certificate, error) {
	mtlsServerCertOnce.Do(func() {
		// The existing certCache.get path mints a server cert with
		// ExtKeyUsageServerAuth via the same CA. Reuse it directly.
		mtlsServerCert, mtlsServerCertErr = certCache.get(host)
	})
	return mtlsServerCert, mtlsServerCertErr
}

// startMTLSListener launches the mTLS inbound listener in a goroutine.
// It blocks on listen errors and logs/exits the goroutine on Accept errors.
func startMTLSListener(cfg *mtlsConfig) error {
	tlsCfg := &tls.Config{
		Certificates:          []tls.Certificate{cfg.ServerCert},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             cfg.OrgCAs,
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: makeRevocationVerifier(cfg.Revoked),
	}
	ln, err := tls.Listen("tcp", cfg.Listen, tlsCfg)
	if err != nil {
		return fmt.Errorf("mtls listen %s: %w", cfg.Listen, err)
	}
	log.Printf("[tls-proxy] mTLS listener on %s (ORG_CA loaded, ClientAuth=RequireAndVerifyClientCert)", cfg.Listen)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("[tls-proxy] mtls accept: %v", err)
				continue
			}
			go handleMTLSConn(conn)
		}
	}()
	return nil
}

// handleMTLSConn forces the TLS handshake to extract peer identity, then
// hands off to handleConn (the existing CONNECT/HTTP processor) with an
// identityConn wrapper so downstream logging can use the cert subject.
func handleMTLSConn(c net.Conn) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		log.Printf("[tls-proxy] mtls: non-TLS conn from %s", c.RemoteAddr())
		c.Close()
		return
	}
	if err := tc.Handshake(); err != nil {
		log.Printf("[tls-proxy] mtls handshake from %s: %v", c.RemoteAddr(), err)
		tc.Close()
		return
	}
	id := extractPeerIdentity(tc.ConnectionState())
	if !id.HasUser() {
		log.Printf("[tls-proxy] mtls: peer cert without CN from %s, rejecting", c.RemoteAddr())
		tc.Close()
		return
	}
	log.Printf("[tls-proxy] mtls accepted: user=%s org=%s remote=%s", id.UserHost, id.OrgID, c.RemoteAddr())
	wrapped := &identityConn{Conn: tc, identity: id}
	handleConn(wrapped)
}

// splitHostNoErr returns the host portion of "host:port" or the input if no
// port is present. Used to derive a SAN for the mTLS server cert.
func splitHostNoErr(addr string) (string, string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return h, p
}

// makeRevocationVerifier returns a tls.Config.VerifyPeerCertificate hook
// that fails the handshake if the leaf cert's serial appears in store.
// When store is nil the returned hook is also nil, leaving the standard
// chain verification untouched.
//
// The hook runs *after* the standard chain verification (because
// ClientAuth=RequireAndVerifyClientCert), so verifiedChains is non-empty
// here.
func makeRevocationVerifier(store *RevokedStore) func([][]byte, [][]*x509.Certificate) error {
	if store == nil {
		return nil
	}
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Prefer the chain that the verifier already built; fall back to
		// parsing rawCerts if for some reason it is empty.
		var leaf *x509.Certificate
		if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
			leaf = verifiedChains[0][0]
		} else if len(rawCerts) > 0 {
			c, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse peer cert: %w", err)
			}
			leaf = c
		}
		if leaf == nil {
			return errors.New("no peer certificate")
		}
		if store.IsRevoked(leaf.SerialNumber) {
			cn := leaf.Subject.CommonName
			serial := leaf.SerialNumber.Text(16)
			log.Printf("[tls-proxy] mtls REJECTED revoked cert: cn=%s serial=%s", cn, serial)
			return fmt.Errorf("client certificate revoked: serial=%s", serial)
		}
		return nil
	}
}
