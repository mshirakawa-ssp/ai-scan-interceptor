package icap

import (
	"bytes"
	"log"
	"net"
	"time"

	"ai-scan-interceptor/detection"
	"ai-scan-interceptor/storage"
)

// ResponseHandler handles ICAP RESPMOD: inspects AI service responses for
// sensitive data leaking from the model back to the client.
type ResponseHandler struct {
	Logger *storage.Logger
}

// ServeRESPMOD inspects each inbound AI service response body for sensitive data.
// If sensitive data is detected it is logged as a warning, but the response is
// always passed through unmodified (WriteNoModification) — blocking responses is
// not yet enforced at this stage.
func (h *ResponseHandler) ServeRESPMOD(conn net.Conn, req *Request) {
	log.Printf("[respmod] received RESPMOD response body=%d", len(req.HTTPBody))

	if len(req.HTTPBody) == 0 {
		log.Printf("[respmod] skip: empty response body")
		WriteNoModification(conn)
		return
	}

	body := req.HTTPBody
	masked := detection.MaskSensitive(body)

	triggered := !bytes.Equal(body, masked)

	host := ""
	path := ""
	if req.HTTPResponse != nil && req.HTTPResponse.Request != nil {
		host = req.HTTPResponse.Request.Host
		path = req.HTTPResponse.Request.URL.Path
	}

	entry := storage.LogEntry{
		Timestamp: time.Now().UTC(),
		Service:   "RESPMOD",
		Host:      host,
		Path:      path,
		Prompt:    truncate(string(body), 512),
		Triggered: triggered,
		Severity:  "",
		ClientIP:  conn.RemoteAddr().String(),
	}

	if triggered {
		log.Printf("[respmod] WARNING: sensitive data detected in AI response body=%d host=%q", len(body), host)
		entry.Severity = "high"
		if h.Logger != nil {
			if err := h.Logger.Write(entry); err != nil {
				log.Printf("[respmod] log write error: %v", err)
			}
		}
	} else {
		log.Printf("[respmod] clean response body=%d host=%q", len(body), host)
	}

	WriteNoModification(conn)
}
