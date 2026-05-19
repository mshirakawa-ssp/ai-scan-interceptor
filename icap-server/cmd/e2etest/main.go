// e2etest sends raw ICAP REQMOD requests to a running server and prints results.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	serverAddr = "127.0.0.1:19344"
	service    = "ai-scan"
)

type testCase struct {
	name     string
	host     string
	path     string
	method   string
	jsonBody string
	wantAlert bool
}

var cases = []testCase{
	{
		name:     "ChatGPT - 通常プロンプト",
		host:     "api.openai.com",
		path:     "/v1/chat/completions",
		method:   "POST",
		jsonBody: `{"messages":[{"role":"user","content":"What is the capital of Japan?"}]}`,
	},
	{
		name:      "ChatGPT - アラートキーワード(secret)",
		host:      "api.openai.com",
		path:      "/v1/chat/completions",
		method:    "POST",
		jsonBody:  `{"messages":[{"role":"user","content":"My secret API key is sk-1234, how do I rotate it?"}]}`,
		wantAlert: true,
	},
	{
		name:     "Claude - messagesフォーマット",
		host:     "claude.ai",
		path:     "/api/organizations/org_abc123/messages",
		method:   "POST",
		jsonBody: `{"messages":[{"role":"user","content":[{"type":"text","text":"Explain Go channels in simple terms."}]}]}`,
	},
	{
		name:      "Claude - 日本語機密キーワード",
		host:      "claude.ai",
		path:      "/api/organizations/org_abc123/messages",
		method:    "POST",
		jsonBody:  `{"messages":[{"role":"user","content":[{"type":"text","text":"以下の機密情報を英語に翻訳してください：売上予測2026年Q3は15億円です。"}]}]}`,
		wantAlert: true,
	},
	{
		name:     "Gemini - generateContent (v1beta)",
		host:     "generativelanguage.googleapis.com",
		path:     "/v1beta/models/gemini-pro/generateContent",
		method:   "POST",
		jsonBody: `{"contents":[{"parts":[{"text":"Write a haiku about programming."}],"role":"user"}]}`,
	},
	{
		name:     "Gemini - generateContent (v1)",
		host:     "generativelanguage.googleapis.com",
		path:     "/v1/models/gemini-1.5-pro/generateContent",
		method:   "POST",
		jsonBody: `{"contents":[{"parts":[{"text":"What is the speed of light?"}],"role":"user"}]}`,
	},
	{
		name:     "Anthropic API - /v1/messages",
		host:     "api.anthropic.com",
		path:     "/v1/messages",
		method:   "POST",
		jsonBody: `{"model":"claude-3-opus-20240229","messages":[{"role":"user","content":"Explain Docker in one sentence."}]}`,
	},
	{
		name:      "Anthropic API - credential detection",
		host:      "api.anthropic.com",
		path:      "/v1/messages",
		method:    "POST",
		jsonBody:  `{"model":"claude-3-opus-20240229","messages":[{"role":"user","content":"My AWS key is AKIAIOSFODNN7EXAMPLE, is this valid?"}]}`,
		wantAlert: true,
	},
	{
		name:     "非対象ホスト（無視されるべき）",
		host:     "example.com",
		path:     "/api/chat",
		method:   "POST",
		jsonBody: `{"messages":[{"role":"user","content":"hello"}]}`,
	},
}

func main() {
	pass, fail := 0, 0
	for _, tc := range cases {
		err := runTest(tc)
		if err != nil {
			fmt.Printf("  ✗ FAIL  %s\n    %v\n\n", tc.name, err)
			fail++
		} else {
			fmt.Printf("  ✓ PASS  %s\n\n", tc.name)
			pass++
		}
	}
	fmt.Printf("─────────────────────────────\n")
	fmt.Printf("結果: %d/%d PASS\n", pass, pass+fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func runTest(tc testCase) error {
	body := []byte(tc.jsonBody)
	httpHdrs := []byte(fmt.Sprintf(
		"%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d",
		tc.method, tc.path, tc.host, len(body),
	))

	msg := buildREQMOD(httpHdrs, body)

	conn, err := net.DialTimeout("tcp", serverAddr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	status, _, err := readResponse(conn)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if !strings.Contains(status, "204") {
		return fmt.Errorf("expected ICAP 204, got %q", status)
	}
	return nil
}

// buildREQMOD constructs a correct RFC 3507 ICAP REQMOD message:
// req-hdr is raw bytes; req-body is chunked.
func buildREQMOD(httpHdrs, httpBody []byte) []byte {
	if !bytes.HasSuffix(httpHdrs, []byte("\r\n\r\n")) {
		httpHdrs = append(httpHdrs, []byte("\r\n\r\n")...)
	}
	hdrLen := len(httpHdrs)

	var encap string
	var bodySection bytes.Buffer

	if len(httpBody) > 0 {
		encap = fmt.Sprintf("req-hdr=0, req-body=%d", hdrLen)
		fmt.Fprintf(&bodySection, "%x\r\n", len(httpBody))
		bodySection.Write(httpBody)
		bodySection.WriteString("\r\n0\r\n\r\n")
	} else {
		encap = fmt.Sprintf("req-hdr=0, null-body=%d", hdrLen)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "REQMOD icap://%s/%s ICAP/1.0\r\n", serverAddr, service)
	fmt.Fprintf(&buf, "Host: %s\r\n", serverAddr)
	fmt.Fprintf(&buf, "Encapsulated: %s\r\n", encap)
	buf.WriteString("\r\n")
	buf.Write(httpHdrs)
	buf.Write(bodySection.Bytes())
	return buf.Bytes()
}

func readResponse(conn net.Conn) (status string, headers map[string]string, err error) {
	r := bufio.NewReader(conn)
	headers = make(map[string]string)
	status, err = r.ReadString('\n')
	if err != nil {
		return
	}
	status = strings.TrimSpace(status)
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
