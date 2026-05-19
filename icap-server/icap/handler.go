package icap

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"strings"
	"time"

	"ai-scan-interceptor/detection"
	"ai-scan-interceptor/notification"
	"ai-scan-interceptor/policy"
	"ai-scan-interceptor/storage"
)

// SIEMExporter is the interface for async SIEM forwarding.
// Using an interface here avoids a circular import with the siem package.
type SIEMExporter interface {
	Send(entry storage.LogEntry)
}

// PromptHandler is the REQMOD handler that extracts and logs AI prompts.
type PromptHandler struct {
	Detector *detection.Detector
	Logger   *storage.Logger
	Notifier *notification.Notifier
	Policy   *policy.Config
	SIEM     SIEMExporter // optional; nil = disabled
}

// ServeREQMOD inspects each outbound HTTP request, extracts any AI prompt,
// logs the result, and enforces the configured policy.
func (h *PromptHandler) ServeREQMOD(conn net.Conn, req *Request) {
	if req.HTTPRequest == nil {
		log.Printf("[handler] skip: no HTTP request")
		WriteNoModification(conn)
		return
	}

	httpReq := req.HTTPRequest
	host := httpReq.Host
	path := httpReq.URL.Path
	method := httpReq.Method

	log.Printf("[handler] REQMOD %s %s%s body=%d", method, host, path, len(req.HTTPBody))

	if len(req.HTTPBody) == 0 {
		log.Printf("[handler] skip: empty body for %s%s", host, path)
		WriteNoModification(conn)
		return
	}

	result, matched := h.Detector.Detect(host, path, method, req.HTTPBody)
	if !matched {
		log.Printf("[handler] no match: %s%s", host, path)
		WriteNoModification(conn)
		return
	}

	// Determine enforcement mode.
	mode := policy.ModeWarn
	if h.Policy != nil {
		mode = h.Policy.GetMode(result.Service)
	}

	// File uploads cannot be safely masked (reconstructed multipart bodies are
	// rejected by upstream servers). Escalate mask→block for file upload requests.
	if result.IsFileUpload && result.Triggered && mode == policy.ModeMask {
		log.Printf("[handler] file upload with sensitive content: escalating mask→block service=%s", result.Service)
		mode = policy.ModeBlock
	}

	// Build rule ID list for storage (avoids importing detection from storage).
	var ruleIDs []string
	for _, rm := range result.RuleMatches {
		ruleIDs = append(ruleIDs, rm.RuleID+":"+rm.Description)
	}

	// Resolve the user identity.
	//   1. X-User-Cert-Subject  (mTLS cert subject, propagated by tls-proxy / Squid)
	//   2. reverse-DNS hostname of X-Client-IP (Squid icap_send_client_ip on)
	//   3. JWT sub claim from Authorization: Bearer ... (unverified)
	//   4. IP only (no identity available)
	userID, identitySource := extractUserID(
		httpReq.Header.Get("X-User-Cert-Subject"),
		lookupHostname(req.Headers["x-client-ip"]),
		httpReq.Header.Get("Authorization"),
	)

	entry := storage.LogEntry{
		Timestamp:      time.Now().UTC(),
		Service:        result.Service,
		Host:           host,
		Path:           path,
		Prompt:         result.Prompt,
		Triggered:      result.Triggered,
		Severity:       result.Severity,
		RuleIDs:        ruleIDs,
		ClientIP:       conn.RemoteAddr().String(),
		UserID:         userID,
		IdentitySource: identitySource,
	}

	// Determine action based on trigger state and enforcement mode.
	if !result.Triggered {
		entry.Action = "passed"
	} else {
		switch mode {
		case policy.ModeBlock:
			entry.Action = "blocked"
		case policy.ModeMask:
			entry.Action = "masked"
		case policy.ModeMonitor:
			entry.Action = "monitored"
		default: // ModeWarn or unrecognised
			entry.Action = "warned"
		}
	}

	if err := h.Logger.Write(entry); err != nil {
		log.Printf("[handler] log write error: %v", err)
	}
	if h.SIEM != nil {
		h.SIEM.Send(entry)
	}

	if result.Triggered {
		log.Printf("[handler] %s service=%s sev=%s rules=%v prompt=%q mode=%s",
			severityLabel(result.Severity),
			result.Service, result.Severity,
			ruleIDs,
			truncate(result.Prompt, 120), mode)

		switch mode {
		case policy.ModeBlock:
			log.Printf("[handler] blocking request: service=%s", result.Service)
			WriteBlock(conn)
			return
		case policy.ModeMask:
			log.Printf("[handler] masking request: service=%s body_before=%d", result.Service, len(req.HTTPBody))
			maskedBody := detection.MaskSensitiveForService(req.HTTPBody, host, path)
			log.Printf("[handler] masking done: body_after=%d changed=%v", len(maskedBody), len(maskedBody) != len(req.HTTPBody))
			WriteMasked(conn, req, maskedBody)
			return
		case policy.ModeMonitor:
			// Log only, no notification.
			WriteNoModification(conn)
			return
		default: // ModeWarn or unrecognised
			// Only send external notifications for high/critical severity to reduce noise.
			// Medium alerts (keyword-only) are logged but not notified externally.
			if shouldNotify(result.Severity) {
				h.Notifier.Send(entry)
			}
			WriteNoModification(conn)
			return
		}
	} else {
		log.Printf("[handler] captured service=%s prompt=%q",
			result.Service, truncate(result.Prompt, 80))
		WriteNoModification(conn)
	}
}

// shouldNotify returns true for high or critical severity alerts.
func shouldNotify(severity string) bool {
	return severity == "critical" || severity == "high"
}

func severityLabel(severity string) string {
	switch severity {
	case "critical":
		return "CRITICAL ALERT"
	case "high":
		return "ALERT"
	default:
		return "ALERT"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// extractUserID resolves a human-readable identity for a request and reports
// the source the value came from. Priority (highest → lowest):
//
//  1. mtls-cert    — X-User-Cert-Subject header (mTLS cert subject CN / DN,
//     propagated by tls-proxy or Squid in Phase 2).
//  2. reverse-dns  — short hostname looked up from X-Client-IP via
//     Squid's icap_send_client_ip.
//  3. jwt-sub      — sub claim from Authorization: Bearer <jwt> (unverified,
//     logging only).
//  4. ip-only      — no identity available; caller falls back to ClientIP.
//
// Returns (userID, source). source is one of "mtls-cert", "reverse-dns",
// "jwt-sub", "ip-only".
func extractUserID(certSubject, hostname, authHeader string) (string, string) {
	if s := strings.TrimSpace(certSubject); s != "" {
		return s, "mtls-cert"
	}
	if hostname != "" {
		return hostname, "reverse-dns"
	}
	if sub := jwtSub(authHeader); sub != "" {
		return sub, "jwt-sub"
	}
	return "", "ip-only"
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
