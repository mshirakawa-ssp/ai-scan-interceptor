// Package monitor implements the periodic integrity check loop:
//   - rc-file managed-block presence + content matches expected
//   - client cert presence + not-yet-expired (and renewal trigger at 50%)
//   - Interceptor reachability (TCP probe to upstream host:port)
package monitor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"ai-scan-connect/config"
	"ai-scan-connect/enroll"
	"ai-scan-connect/envvars"
)

// DefaultInterval is the polling cadence.
const DefaultInterval = 60 * time.Second

// Report summarizes a single check.
type Report struct {
	Time            time.Time
	RCDrift         []string
	CertExpired     bool
	CertNeedsRenew  bool
	UpstreamReachable bool
	Err             error
}

// Run loops until ctx is cancelled, calling CheckAndRecover every interval.
func Run(ctx context.Context, cfg *config.Config, paths enroll.Paths, interval time.Duration, logger *log.Logger) error {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if logger == nil {
		logger = log.Default()
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	// Run once immediately so the first report is fresh.
	r := CheckAndRecover(ctx, cfg, paths)
	logReport(logger, r)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r := CheckAndRecover(ctx, cfg, paths)
			logReport(logger, r)
		}
	}
}

func logReport(l *log.Logger, r Report) {
	l.Printf("monitor: rc_drift=%d cert_expired=%v cert_needs_renew=%v upstream=%v err=%v",
		len(r.RCDrift), r.CertExpired, r.CertNeedsRenew, r.UpstreamReachable, r.Err)
}

// CheckAndRecover does one pass of integrity checks and applies safe recovery
// (currently: re-write rc managed block on drift). Cert renewal is reported
// but not auto-performed here in Phase 1; the install/enroll subcommands own that.
func CheckAndRecover(ctx context.Context, cfg *config.Config, paths enroll.Paths) Report {
	r := Report{Time: time.Now()}

	// 1) rc files
	mgr := envvars.New()
	v := envvars.Vars{
		HTTPSProxy:       "http://" + cfg.LocalListen,
		HTTPProxy:        "http://" + cfg.LocalListen,
		NodeExtraCACerts: config.DefaultCAInstallPath(),
		RequestsCABundle: config.DefaultCAInstallPath(),
		SSLCertFile:      config.DefaultCAInstallPath(),
	}
	drift, err := mgr.CheckIntegrity(v)
	if err != nil && !errors.Is(err, envvars.ErrNotImplemented) {
		r.Err = fmt.Errorf("rc check: %w", err)
	}
	r.RCDrift = drift
	if len(drift) > 0 {
		// Recover: re-apply the block.
		if _, aerr := mgr.Apply(v); aerr != nil && !errors.Is(aerr, envvars.ErrNotImplemented) {
			r.Err = errors.Join(r.Err, fmt.Errorf("rc recover: %w", aerr))
		}
	}

	// 2) cert
	cert, err := enroll.LoadCert(paths.CertPath)
	if err != nil {
		// Treat missing/invalid as "needs renew" so the operator notices.
		r.CertNeedsRenew = true
	} else {
		now := time.Now()
		if now.After(cert.NotAfter) {
			r.CertExpired = true
			r.CertNeedsRenew = true
		} else if enroll.ShouldRenew(cert, now) {
			r.CertNeedsRenew = true
		}
	}

	// 3) upstream reachability (TCP only; no full mTLS to keep cheap).
	r.UpstreamReachable = probeTCP(ctx, cfg.InterceptorURL, 5*time.Second)

	return r
}

// probeTCP returns true if a TCP dial to the URL's host:port succeeds.
func probeTCP(ctx context.Context, raw string, timeout time.Duration) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":3128"
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// ProbeMTLS optionally validates the full mTLS handshake. Not used by the
// periodic loop in Phase 1 (too heavy per-tick), exposed for `status`.
func ProbeMTLS(ctx context.Context, cfg *config.Config, certPath, keyPath string) error {
	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load client cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.OrgCAPEM)) {
		return errors.New("invalid org_ca_pem")
	}
	u, err := url.Parse(cfg.InterceptorURL)
	if err != nil {
		return err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":3128"
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{clientCert},
			MinVersion:   tls.VersionTLS12,
			ServerName:   strings.SplitN(host, ":", 2)[0],
		},
	}
	c, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return err
	}
	return c.Close()
}
