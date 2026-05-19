package notification

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// testSMTPServer is a minimal SMTP server for testing.
type testSMTPServer struct {
	ln       net.Listener
	mu       sync.Mutex
	received []string
}

func newTestSMTPServer(t *testing.T) *testSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSMTPServer{ln: ln}
	go s.run()
	return s
}

func (s *testSMTPServer) addr() string { return s.ln.Addr().String() }

func (s *testSMTPServer) run() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *testSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	w := func(line string) { conn.Write([]byte(line + "\r\n")) }
	r := bufio.NewReader(conn)

	w("220 test.local ESMTP")

	var msgBuf strings.Builder
	inData := false

	for {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)

		if inData {
			if line == "." {
				s.mu.Lock()
				s.received = append(s.received, msgBuf.String())
				s.mu.Unlock()
				msgBuf.Reset()
				inData = false
				w("250 OK: message accepted")
			} else {
				// Unstuff leading dot
				if strings.HasPrefix(line, "..") {
					line = line[1:]
				}
				msgBuf.WriteString(line + "\n")
			}
			continue
		}

		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			w("250-test.local\r\n250 AUTH PLAIN LOGIN")
		case strings.HasPrefix(up, "AUTH"):
			w("235 Authentication successful")
		case strings.HasPrefix(up, "MAIL FROM"):
			w("250 OK")
		case strings.HasPrefix(up, "RCPT TO"):
			w("250 OK")
		case up == "DATA":
			w("354 End data with <CR LF>.<CR LF>")
			inData = true
		case up == "QUIT":
			w("221 Bye")
			return
		default:
			w("250 OK")
		}
	}
}

func (s *testSMTPServer) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.received))
	copy(out, s.received)
	return out
}

// ---- Tests ----

func TestEmailSend(t *testing.T) {
	srv := newTestSMTPServer(t)
	defer srv.ln.Close()
	time.Sleep(20 * time.Millisecond)

	host, port, _ := net.SplitHostPort(srv.addr())
	cfg := EmailConfig{
		Host:     host,
		Port:     port,
		User:     "user",
		Password: "pass",
		From:     "alert@example.com",
		To:       []string{"admin@example.com"},
	}
	en := NewEmailNotifier(cfg)
	if en == nil {
		t.Fatal("expected non-nil EmailNotifier")
	}

	if err := en.Send("Test Subject", "Hello, this is a test alert body."); err != nil {
		t.Fatalf("Send: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	msgs := srv.messages()
	if len(msgs) == 0 {
		t.Fatal("no message received by test SMTP server")
	}
	if !strings.Contains(msgs[0], "Test Subject") {
		t.Errorf("subject not found:\n%s", msgs[0])
	}
	if !strings.Contains(msgs[0], "Hello, this is a test alert body.") {
		t.Errorf("body not found:\n%s", msgs[0])
	}
}

func TestEmailNotifier_Disabled(t *testing.T) {
	if NewEmailNotifier(EmailConfig{}) != nil {
		t.Error("expected nil for empty host")
	}
	if NewEmailNotifier(EmailConfig{Host: "smtp.example.com"}) != nil {
		t.Error("expected nil when To is empty")
	}
}

func TestNotifier_NoPanic_NoChannels(t *testing.T) {
	n := NewNotifier("", nil)
	entry := map[string]interface{}{
		"timestamp": "2026-04-24T00:00:00Z",
		"service":   "ChatGPT",
		"host":      "api.openai.com",
		"path":      "/v1/chat/completions",
		"prompt":    "test prompt",
		"triggered": true,
		"keywords":  []string{"secret"},
		"client_ip": "127.0.0.1",
	}
	n.Send(entry)          // must not panic
	time.Sleep(50 * time.Millisecond)
}

func TestEmailBody_Format(t *testing.T) {
	srv := newTestSMTPServer(t)
	defer srv.ln.Close()
	time.Sleep(20 * time.Millisecond)

	host, port, _ := net.SplitHostPort(srv.addr())
	en := NewEmailNotifier(EmailConfig{
		Host: host, Port: port,
		User: "u", Password: "p",
		From: "from@x.com", To: []string{"to@x.com"},
	})

	n := NewNotifier("", en)
	entry := map[string]interface{}{
		"timestamp": "2026-04-24T04:15:00Z",
		"service":   "Claude",
		"host":      "claude.ai",
		"path":      "/api/organizations/org1/messages",
		"prompt":    "[user] この機密情報を要約してください",
		"triggered": true,
		"keywords":  []string{"機密"},
		"client_ip": "10.0.0.5",
	}
	n.Send(entry)
	time.Sleep(200 * time.Millisecond)

	msgs := srv.messages()
	if len(msgs) == 0 {
		t.Fatal("no message received")
	}
	msg := msgs[0]
	for _, want := range []string{"Claude", "claude.ai", "機密", "10.0.0.5"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in email body:\n%s", want, msg)
		}
	}
}
