// Package icap implements a minimal ICAP/1.0 server (RFC 3507).
// Supports REQMOD and RESPMOD; the server returns 204 (no modifications) by default.
package icap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const (
	icapVersion = "ICAP/1.0"
	isTag       = `"AI-SCAN-1.0"`
	// Hard limits to prevent memory exhaustion
	maxChunkSize = 16 << 20  // 16 MB per chunk
	maxBodySize  = 32 << 20  // 32 MB total body
)

// Request is a parsed ICAP request including the encapsulated HTTP data.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	// Parsed encapsulated HTTP request (nil for OPTIONS and RESPMOD)
	HTTPRequest *http.Request
	// Parsed encapsulated HTTP response (nil for OPTIONS and REQMOD)
	HTTPResponse *http.Response
	// Raw body bytes of the encapsulated HTTP request or response body
	HTTPBody []byte
	// Raw bytes of the encapsulated HTTP headers (before parsing)
	RawHTTPHeaders []byte
}

// Handler processes ICAP REQMOD requests.
type Handler interface {
	ServeREQMOD(conn net.Conn, req *Request)
}

// RESPMODHandler processes ICAP RESPMOD requests.
type RESPMODHandler interface {
	ServeRESPMOD(conn net.Conn, req *Request)
}

// Server is a TCP server that speaks ICAP/1.0.
type Server struct {
	Addr           string
	Handler        Handler
	RESPMODHandler RESPMODHandler
}

// ListenAndServe starts the ICAP TCP listener.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve accepts connections on an already-open listener.
// Useful in tests where a random port must be reserved before starting.
func (s *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	log.Printf("[icap] listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("[icap] connection open from %s", remote)
	defer log.Printf("[icap] connection closed from %s", remote)
	r := bufio.NewReaderSize(conn, 65536)
	for {
		req, err := readRequest(r)
		if err != nil {
			if err != io.EOF && !isClosedErr(err) {
				log.Printf("[icap] read error from %s: %v", remote, err)
			} else {
				log.Printf("[icap] connection ended from %s: %v", remote, err)
			}
			return
		}
		switch req.Method {
		case "OPTIONS":
			writeOptions(conn)
		case "REQMOD":
			s.Handler.ServeREQMOD(conn, req)
		case "RESPMOD":
			if s.RESPMODHandler != nil {
				s.RESPMODHandler.ServeRESPMOD(conn, req)
			} else {
				WriteNoModification(conn)
			}
		default:
			fmt.Fprintf(conn, "%s 405 Method Not Allowed\r\n\r\n", icapVersion)
		}
	}
}

// WriteNoModification writes an ICAP 204 response (pass-through).
func WriteNoModification(conn net.Conn) {
	fmt.Fprintf(conn, "%s 204 No Modifications Needed\r\nISTag: %s\r\n\r\n", icapVersion, isTag)
}

// WriteBlock sends an ICAP 200 response that encapsulates an HTTP 403 Forbidden,
// instructing the ICAP client (Squid) to block the request.
func WriteBlock(conn net.Conn) {
	body := []byte(`{"error":"Request blocked by AI governance policy"}`)
	httpRespHdr := fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n",
		len(body),
	)
	icapHdr := fmt.Sprintf(
		"%s 200 OK\r\nISTag: %s\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n",
		icapVersion, isTag, len(httpRespHdr),
	)
	fmt.Fprintf(conn, "%s%s%x\r\n", icapHdr, httpRespHdr, len(body))
	conn.Write(body)
	fmt.Fprint(conn, "\r\n0\r\n\r\n")
}

// WriteMasked sends an ICAP 200 REQMOD response with the original request
// headers and maskedBody as the chunked body.
func WriteMasked(conn net.Conn, req *Request, maskedBody []byte) {
	if req == nil {
		WriteNoModification(conn)
		return
	}

	var reqHdrBytes []byte
	if len(req.RawHTTPHeaders) > 0 {
		// Preferred path: return Squid's own header bytes verbatim, only updating
		// Content-Length to match the new body size.  Because these bytes came from
		// Squid's own HTTP parser in the first place, Squid is guaranteed to accept
		// them on the return trip — avoiding any re-encoding differences introduced
		// by Go's http.Header.Write().
		reqHdrBytes = rawUpdateContentLength(req.RawHTTPHeaders, len(maskedBody))
		log.Printf("[icap] WriteMasked: using raw headers (len=%d, body=%d)", len(reqHdrBytes), len(maskedBody))
	} else if req.HTTPRequest != nil {
		// Fallback: rebuild headers from parsed request when raw bytes are unavailable.
		var hdrBuf bytes.Buffer
		httpReq := req.HTTPRequest
		fmt.Fprintf(&hdrBuf, "%s %s HTTP/1.1\r\n", httpReq.Method, httpReq.URL.RequestURI())
		if httpReq.Host != "" {
			fmt.Fprintf(&hdrBuf, "Host: %s\r\n", httpReq.Host)
		}
		httpReq.Header.Del("Transfer-Encoding")
		httpReq.Header.Set("Content-Length", strconv.Itoa(len(maskedBody)))
		httpReq.Header.Write(&hdrBuf)
		fmt.Fprint(&hdrBuf, "\r\n")
		reqHdrBytes = hdrBuf.Bytes()
		log.Printf("[icap] WriteMasked: using rebuilt headers (len=%d, body=%d)", len(reqHdrBytes), len(maskedBody))
	} else {
		log.Printf("[icap] WriteMasked: no HTTP headers available; sending 204")
		WriteNoModification(conn)
		return
	}

	icapHdr := fmt.Sprintf(
		"%s 200 OK\r\nISTag: %s\r\nEncapsulated: req-hdr=0, req-body=%d\r\n\r\n",
		icapVersion, isTag, len(reqHdrBytes),
	)
	fmt.Fprint(conn, icapHdr)
	conn.Write(reqHdrBytes)
	fmt.Fprintf(conn, "%x\r\n", len(maskedBody))
	conn.Write(maskedBody)
	fmt.Fprint(conn, "\r\n0\r\n\r\n")
}

// rawUpdateContentLength replaces (or inserts) the Content-Length value in raw
// HTTP header bytes.  If no Content-Length line exists, one is inserted before
// the terminal blank line.
func rawUpdateContentLength(headers []byte, newLen int) []byte {
	s := string(headers)
	lower := strings.ToLower(s)
	clLine := fmt.Sprintf("Content-Length: %d", newLen)

	start := strings.Index(lower, "\ncontent-length:")
	if start != -1 {
		start++ // skip the leading \n
		end := strings.Index(s[start:], "\r\n")
		if end != -1 {
			return []byte(s[:start] + clLine + s[start+end:])
		}
	}
	// No Content-Length found; insert before the blank line that terminates headers.
	terminator := strings.LastIndex(s, "\r\n\r\n")
	if terminator != -1 {
		return []byte(s[:terminator+2] + clLine + "\r\n\r\n")
	}
	return headers
}

func writeOptions(conn net.Conn) {
	fmt.Fprintf(conn,
		"%s 200 OK\r\n"+
			"Methods: REQMOD, RESPMOD\r\n"+
			"Service: AI-Scan-Interceptor/1.0\r\n"+
			"ISTag: %s\r\n"+
			"Max-Connections: 100\r\n"+
			"Options-TTL: 3600\r\n"+
			"Allow: 204\r\n"+
			"\r\n",
		icapVersion, isTag,
	)
}

// readRequest parses one ICAP request from r.
func readRequest(r *bufio.Reader) (*Request, error) {
	// --- Start line (skip leading blank lines — some ICAP clients send keep-alive pings) ---
	var line string
	for {
		var err error
		line, err = r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			break
		}
		// blank line: skip and read again
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || parts[2] != icapVersion {
		return nil, fmt.Errorf("invalid ICAP start line: %q", line)
	}
	req := &Request{
		Method:  parts[0],
		URL:     parts[1],
		Headers: make(map[string]string),
	}

	// --- ICAP Headers ---
	for {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hdr = strings.TrimSpace(hdr)
		if hdr == "" {
			break
		}
		if idx := strings.IndexByte(hdr, ':'); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(hdr[:idx]))
			v := strings.TrimSpace(hdr[idx+1:])
			req.Headers[k] = v
		}
	}

	if req.Method == "OPTIONS" {
		return req, nil
	}

	// --- Parse Encapsulated header ---
	// REQMOD: "req-hdr=0, req-body=412" or "req-hdr=0, null-body=412"
	// RESPMOD: "res-hdr=0, res-body=N" or "res-hdr=0, null-body=N"
	//
	// Per RFC 3507 §4.4.1 and §4.5:
	//   - hdr section: raw bytes (NOT chunked) — length = body/null-body offset
	//   - body section: chunked transfer encoding (present only when last section is *-body)
	//   - null-body: message ends after hdr bytes; no chunked terminator
	encap := req.Headers["encapsulated"]
	hdrLen, hasBody := parseEncapsulated(encap)

	// --- Read header section (raw bytes) ---
	var hdrBytes, bodyBytes []byte
	if hdrLen > 0 {
		hdrBytes = make([]byte, hdrLen)
		if _, err := io.ReadFull(r, hdrBytes); err != nil {
			return nil, fmt.Errorf("hdr read (%d bytes): %w", hdrLen, err)
		}
	}

	// --- Read body section (chunked) ---
	if hasBody {
		var err error
		bodyBytes, err = readChunked(r)
		if err != nil {
			return nil, fmt.Errorf("body chunked read: %w", err)
		}
	}

	// --- Parse encapsulated HTTP headers ---
	req.RawHTTPHeaders = hdrBytes
	if len(hdrBytes) > 0 {
		if req.Method == "RESPMOD" {
			// Parse as HTTP response headers
			httpResp, parseErr := http.ReadResponse(bufio.NewReader(bytes.NewReader(hdrBytes)), nil)
			if parseErr == nil {
				req.HTTPResponse = httpResp
			}
		} else {
			// Parse as HTTP request headers (REQMOD)
			httpReq, parseErr := http.ReadRequest(bufio.NewReader(bytes.NewReader(hdrBytes)))
			if parseErr == nil {
				req.HTTPRequest = httpReq
			} else {
				log.Printf("[icap] readRequest: http.ReadRequest failed: %v (hdrLen=%d)", parseErr, hdrLen)
			}
		}
	}
	req.HTTPBody = bodyBytes

	return req, nil
}

// parseEncapsulated returns the byte length of the header section and whether
// a body section follows (i.e. chunked body present vs null-body).
// Handles both REQMOD ("req-hdr=0, req-body=N") and RESPMOD ("res-hdr=0, res-body=N")
// Encapsulated header formats, as well as "null-body=N".
func parseEncapsulated(s string) (hdrLen int, hasBody bool) {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val, _ := strconv.Atoi(strings.TrimSpace(kv[1]))
		switch key {
		case "req-body", "res-body":
			hdrLen = val
			hasBody = true
		case "null-body":
			hdrLen = val
			hasBody = false
		}
	}
	return
}

// readChunked reads HTTP/1.1 chunked-encoded data until the terminal zero-chunk.
func readChunked(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		sizeLine, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("chunk size: %w", err)
		}
		sizeLine = strings.TrimSpace(sizeLine)
		// Strip chunk extensions (e.g. "a; ieof")
		if semi := strings.IndexByte(sizeLine, ';'); semi >= 0 {
			sizeLine = sizeLine[:semi]
		}
		chunkSize, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk size %q: %w", sizeLine, err)
		}
		if chunkSize == 0 {
			r.ReadString('\n') // consume trailing CRLF
			break
		}
		if chunkSize > maxChunkSize {
			return nil, fmt.Errorf("chunk size %d exceeds limit", chunkSize)
		}
		if buf.Len()+int(chunkSize) > maxBodySize {
			return nil, fmt.Errorf("total body exceeds %d bytes", maxBodySize)
		}
		chunk := make([]byte, chunkSize)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, fmt.Errorf("chunk data: %w", err)
		}
		buf.Write(chunk)
		r.ReadString('\n') // consume trailing CRLF after chunk data
	}
	return buf.Bytes(), nil
}

func isClosedErr(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "connection reset by peer")
}
