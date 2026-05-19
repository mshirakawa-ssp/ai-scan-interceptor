package proxy

import (
	"bufio"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestForwarder_RejectsNonConnect verifies that a GET request is rejected.
func TestForwarder_RejectsNonConnect(t *testing.T) {
	f := &Forwarder{
		ListenAddr:          "127.0.0.1:0",
		InterceptorHostPort: "127.0.0.1:1", // unreachable on purpose
		RootCAs:             x509.NewCertPool(),
		FailClose:           true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = f.ListenAndServe(ctx) }()

	addr := waitForListen(t, f)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestForwarder_FailCloseOnBadUpstream: with fail_close=true and an unreachable
// upstream, CONNECT should yield a 503.
func TestForwarder_FailCloseOnBadUpstream(t *testing.T) {
	f := &Forwarder{
		ListenAddr:          "127.0.0.1:0",
		InterceptorHostPort: "127.0.0.1:1", // unreachable
		RootCAs:             x509.NewCertPool(),
		FailClose:           true,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.ListenAndServe(ctx) }()

	addr := waitForListen(t, f)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestHostPortFromURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://acme.example.com", "acme.example.com:3128"},
		{"https://acme.example.com:3128", "acme.example.com:3128"},
		{"https://1.2.3.4:9000", "1.2.3.4:9000"},
	}
	for _, c := range cases {
		got, err := hostPortFromURL(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("%s -> %s, want %s", c.in, got, c.want)
		}
	}
}

func waitForListen(t *testing.T, f *Forwarder) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a := f.Addr(); a != nil {
			return a.String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("forwarder did not bind in time")
	return ""
}
