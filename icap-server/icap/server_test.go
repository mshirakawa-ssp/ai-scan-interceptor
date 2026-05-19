package icap_test

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-scan-interceptor/icap"
)

// mockHandler records calls for assertion.
type mockHandler struct {
	mu      sync.Mutex
	calls   []*icap.Request
	respond func(conn net.Conn, req *icap.Request)
}

func (m *mockHandler) ServeREQMOD(conn net.Conn, req *icap.Request) {
	m.mu.Lock()
	m.calls = append(m.calls, req)
	m.mu.Unlock()
	if m.respond != nil {
		m.respond(conn, req)
	} else {
		icap.WriteNoModification(conn)
	}
}

func (m *mockHandler) lastCall() *icap.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return nil
	}
	return m.calls[len(m.calls)-1]
}

// startTestServer spins up a server on a random port and returns its address.
func startTestServer(t *testing.T, h *mockHandler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv := &icap.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	return addr
}

// buildICAPREQMOD constructs a raw ICAP REQMOD message per RFC 3507 §4.4.1:
//   - req-hdr section: raw bytes (NOT chunked)
//   - req-body section: chunked transfer encoding (only when body is present)
//   - null-body: message ends after req-hdr bytes
func buildICAPREQMOD(addr, service string, httpHeaders, httpBody []byte) []byte {
	// Ensure headers end with \r\n\r\n
	if !bytes.HasSuffix(httpHeaders, []byte("\r\n\r\n")) {
		httpHeaders = append(httpHeaders, []byte("\r\n\r\n")...)
	}
	reqHdrLen := len(httpHeaders)

	var encap string
	var afterHeaders bytes.Buffer

	if len(httpBody) > 0 {
		encap = fmt.Sprintf("req-hdr=0, req-body=%d", reqHdrLen)
		// req-body: chunked
		fmt.Fprintf(&afterHeaders, "%x\r\n", len(httpBody))
		afterHeaders.Write(httpBody)
		afterHeaders.WriteString("\r\n0\r\n\r\n")
	} else {
		encap = fmt.Sprintf("req-hdr=0, null-body=%d", reqHdrLen)
		// null-body: nothing after req-hdr
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "REQMOD icap://%s/%s ICAP/1.0\r\n", addr, service)
	fmt.Fprintf(&buf, "Host: %s\r\n", addr)
	fmt.Fprintf(&buf, "Encapsulated: %s\r\n", encap)
	buf.WriteString("\r\n")
	buf.Write(httpHeaders)      // req-hdr: raw
	buf.Write(afterHeaders.Bytes()) // req-body: chunked (or empty for null-body)
	return buf.Bytes()
}

func readICAPResponse(conn net.Conn) (statusLine string, headers map[string]string, err error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	headers = make(map[string]string)

	statusLine, err = r.ReadString('\n')
	if err != nil {
		return
	}
	statusLine = strings.TrimSpace(statusLine)

	for {
		line, e := r.ReadString('\n')
		if e != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:idx]))
			v := strings.TrimSpace(line[idx+1:])
			headers[k] = v
		}
	}
	return
}

// ---- Tests ----

func TestOPTIONS(t *testing.T) {
	h := &mockHandler{}
	addr := startTestServer(t, h)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "OPTIONS icap://%s/ai-scan ICAP/1.0\r\nHost: %s\r\n\r\n", addr, addr)

	status, hdrs, err := readICAPResponse(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Errorf("OPTIONS: want 200, got %q", status)
	}
	if !strings.Contains(hdrs["methods"], "REQMOD") {
		t.Errorf("OPTIONS: methods header missing REQMOD: %v", hdrs)
	}
}

func TestREQMOD_ChatGPT(t *testing.T) {
	h := &mockHandler{}
	addr := startTestServer(t, h)

	jsonBody := []byte(`{"messages":[{"role":"user","content":"What is 2+2?"}]}`)
	httpHdrs := []byte(fmt.Sprintf(
		"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: %d",
		len(jsonBody),
	))

	msg := buildICAPREQMOD(addr, "ai-scan", httpHdrs, jsonBody)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write(msg)

	status, _, err := readICAPResponse(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "204") {
		t.Errorf("REQMOD: want 204, got %q", status)
	}

	call := h.lastCall()
	if call == nil {
		t.Fatal("handler was not called")
	}
	if call.HTTPRequest == nil {
		t.Fatal("HTTPRequest not parsed")
	}
	if call.HTTPRequest.Host != "api.openai.com" {
		t.Errorf("host=%q", call.HTTPRequest.Host)
	}
	if !bytes.Contains(call.HTTPBody, []byte("What is 2+2?")) {
		t.Errorf("body not captured: %q", call.HTTPBody)
	}
}

func TestREQMOD_Claude(t *testing.T) {
	h := &mockHandler{}
	addr := startTestServer(t, h)

	jsonBody := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"Summarize Go generics."}]}]}`)
	httpHdrs := []byte(fmt.Sprintf(
		"POST /api/organizations/org1/messages HTTP/1.1\r\nHost: claude.ai\r\nContent-Type: application/json\r\nContent-Length: %d",
		len(jsonBody),
	))

	msg := buildICAPREQMOD(addr, "ai-scan", httpHdrs, jsonBody)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write(msg)

	status, _, _ := readICAPResponse(conn)
	if !strings.Contains(status, "204") {
		t.Errorf("Claude: want 204, got %q", status)
	}
	call := h.lastCall()
	if call == nil || call.HTTPRequest == nil {
		t.Fatal("handler not called or HTTP not parsed")
	}
	if call.HTTPRequest.Host != "claude.ai" {
		t.Errorf("host=%q", call.HTTPRequest.Host)
	}
}

func TestREQMOD_NullBody(t *testing.T) {
	// GET request has no body → null-body in ICAP
	h := &mockHandler{}
	addr := startTestServer(t, h)

	httpHdrs := []byte("GET /v1/models HTTP/1.1\r\nHost: api.openai.com")
	msg := buildICAPREQMOD(addr, "ai-scan", httpHdrs, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write(msg)

	status, _, _ := readICAPResponse(conn)
	if !strings.Contains(status, "204") {
		t.Errorf("null-body: want 204, got %q", status)
	}
}

// TestWriteMasked_HostHeader verifies that WriteMasked includes the Host header
// in the encapsulated HTTP request — required by HTTP/1.1 and Squid's parsePart.
func TestWriteMasked_HostHeader(t *testing.T) {
	maskedBody := []byte(`f.req=%5B%5BREDACTED%5D%5D`)
	h := &mockHandler{
		respond: func(conn net.Conn, req *icap.Request) {
			icap.WriteMasked(conn, req, maskedBody)
		},
	}
	addr := startTestServer(t, h)

	body := []byte("f.req=%5Bnull%2CAWS_SECRET_ACCESS_KEY%3DTEST123%5D")
	httpHdrs := []byte(fmt.Sprintf(
		"POST /_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?rt=c HTTP/1.1\r\n"+
			"Host: gemini.google.com\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d",
		len(body),
	))
	msg := buildICAPREQMOD(addr, "ai-scan", httpHdrs, body)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(msg)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read full ICAP response
	var respBuf bytes.Buffer
	tmp := make([]byte, 32768)
	for {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			respBuf.Write(tmp[:n])
		}
		if readErr != nil {
			break
		}
		// Stop once we have the zero-chunk terminator
		if bytes.Contains(respBuf.Bytes(), []byte("\r\n0\r\n\r\n")) {
			break
		}
	}
	respStr := respBuf.String()

	if !strings.HasPrefix(respStr, "ICAP/1.0 200") {
		t.Fatalf("expected ICAP 200, got: %q", respStr[:min(100, len(respStr))])
	}

	// The encapsulated HTTP headers start after the double-CRLF of the ICAP headers.
	icapHdrEnd := strings.Index(respStr, "\r\n\r\n")
	if icapHdrEnd < 0 {
		t.Fatal("no ICAP header terminator found")
	}
	encapSection := respStr[icapHdrEnd+4:]

	// Simulate Squid's parsePart: parse the encapsulated HTTP request headers.
	httpReq, parseErr := http.ReadRequest(bufio.NewReader(strings.NewReader(encapSection)))
	if parseErr != nil {
		t.Fatalf("Squid parsePart simulation failed: %v\nResponse:\n%s", parseErr, respStr[:min(500, len(respStr))])
	}
	if httpReq.Host == "" {
		t.Error("Host header missing from WriteMasked response")
	}
	if httpReq.Host != "gemini.google.com" {
		t.Errorf("expected Host=gemini.google.com, got %q", httpReq.Host)
	}
	if httpReq.ContentLength != int64(len(maskedBody)) {
		t.Errorf("expected Content-Length=%d, got %d", len(maskedBody), httpReq.ContentLength)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestREQMOD_PersistentConnection(t *testing.T) {
	// Send two REQMOD requests on the same connection
	h := &mockHandler{}
	addr := startTestServer(t, h)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for i := 0; i < 2; i++ {
		jsonBody := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":"Request %d"}]}`, i))
		httpHdrs := []byte(fmt.Sprintf(
			"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: %d",
			len(jsonBody),
		))
		msg := buildICAPREQMOD(addr, "ai-scan", httpHdrs, jsonBody)
		conn.Write(msg)

		status, _, err := readICAPResponse(conn)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if !strings.Contains(status, "204") {
			t.Errorf("request %d: want 204, got %q", i, status)
		}
	}

	h.mu.Lock()
	if len(h.calls) != 2 {
		t.Errorf("expected 2 handler calls, got %d", len(h.calls))
	}
	h.mu.Unlock()
}
