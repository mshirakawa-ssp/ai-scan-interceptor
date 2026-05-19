package detection

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"mime/multipart"
	"net/url"
	"strings"
)

// MaskSensitive replaces structured-credential matches in body with [REDACTED]
// by scanning raw bytes. Only rules with MaskBody=true are applied.
// Kept for backward compatibility and RESPMOD detection use.
func MaskSensitive(body []byte) []byte {
	result := body
	for _, r := range ActiveRules() {
		if !r.MaskBody {
			continue
		}
		repl := r.MaskReplacement
		if repl == "" {
			repl = "[REDACTED]"
		}
		result = r.Pattern.ReplaceAll(result, []byte(repl))
	}
	return result
}

// MaskSensitiveForService applies service-aware masking.
// For JSON services it masks within decoded string values, avoiding failures
// caused by JSON escape sequences (\n, \", \/) that break raw-byte regex matching.
// For Gemini-Web it URL-decodes the form body before masking.
// For multipart/form-data (file uploads) it masks each text part individually.
// Falls back to raw-byte MaskSensitive if the service cannot be identified.
func MaskSensitiveForService(body []byte, host, path string) []byte {
	// Multipart bodies start with "--<boundary>". Handle them before service routing
	// so that file upload requests are masked regardless of which AI service rule matches.
	if len(body) > 2 && body[0] == '-' && body[1] == '-' {
		return maskMultipartBody(body)
	}
	rule := findRule(host, path)
	if rule == nil {
		return MaskSensitive(body)
	}
	if rule.Name == "Gemini-Web" {
		return maskGeminiWebBody(body)
	}
	return maskJSONStrings(body)
}

// maskMultipartBody masks credentials inside text/plain parts of a multipart/form-data body.
// Boundaries and non-text parts are passed through unchanged.
func maskMultipartBody(body []byte) []byte {
	bodyStr := string(body)
	lineEnd := strings.Index(bodyStr, "\r\n")
	if lineEnd < 3 || bodyStr[0] != '-' || bodyStr[1] != '-' {
		return MaskSensitive(body)
	}
	boundary := bodyStr[2:lineEnd]

	mr := multipart.NewReader(strings.NewReader(bodyStr), boundary)

	// Rebuild the multipart body with masked text parts.
	// We split the original body string on the boundary marker and replace
	// text/plain part bodies in-place, preserving all headers and structure.
	var out bytes.Buffer
	firstPart := true
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		data, readErr := io.ReadAll(part)
		if readErr != nil {
			part.Close()
			return MaskSensitive(body) // fallback
		}

		ct := part.Header.Get("Content-Type")
		filename := part.FileName()
		isText := strings.HasPrefix(ct, "text/") ||
			(filename != "" && (ct == "" || strings.Contains(ct, "octet-stream")))

		// Write boundary
		if !firstPart {
			out.WriteString("\r\n")
		}
		firstPart = false
		out.WriteString("--")
		out.WriteString(boundary)
		out.WriteString("\r\n")

		// Write part headers (textproto.MIMEHeader)
		for k, vals := range part.Header {
			for _, v := range vals {
				out.WriteString(k)
				out.WriteString(": ")
				out.WriteString(v)
				out.WriteString("\r\n")
			}
		}
		out.WriteString("\r\n")

		// Write part body, masking text/plain file contents
		if isText {
			out.WriteString(applyMaskPatterns(string(data)))
		} else {
			out.Write(data)
		}
		part.Close()
	}

	// Write final boundary
	out.WriteString("\r\n--")
	out.WriteString(boundary)
	out.WriteString("--\r\n")

	// Sanity check: if we produced no content, fall back to raw masking
	if out.Len() == 0 {
		return MaskSensitive(body)
	}
	log.Printf("[mask] maskMultipartBody: before=%d after=%d", len(body), out.Len())
	return out.Bytes()
}

// maskJSONStrings parses a JSON body, applies masking rules to every string
// value recursively, and re-serialises. Returns the original body unchanged
// if parsing fails or no pattern matches.
func maskJSONStrings(body []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // preserve numeric precision on re-serialise
	var raw interface{}
	if err := dec.Decode(&raw); err != nil {
		return MaskSensitive(body)
	}
	if !maskAny(&raw) {
		return body
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep <, >, & as literal characters
	if err := enc.Encode(raw); err != nil {
		return body
	}
	result := buf.Bytes()
	// json.Encoder appends a trailing newline; strip it to match original framing
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}
	return result
}

// maskAny walks a decoded JSON value and masks all string leaves in-place.
// Returns true if at least one substitution was made.
func maskAny(v *interface{}) bool {
	if v == nil {
		return false
	}
	switch val := (*v).(type) {
	case string:
		masked := applyMaskPatterns(val)
		if masked != val {
			*v = masked
			return true
		}
	case map[string]interface{}:
		changed := false
		for k := range val {
			item := val[k]
			if maskAny(&item) {
				val[k] = item
				changed = true
			}
		}
		return changed
	case []interface{}:
		changed := false
		for i := range val {
			item := val[i]
			if maskAny(&item) {
				val[i] = item
				changed = true
			}
		}
		return changed
	}
	return false
}

// applyMaskPatterns replaces all active masking-rule patterns in text.
func applyMaskPatterns(text string) string {
	result := text
	for _, r := range ActiveRules() {
		if !r.MaskBody {
			continue
		}
		repl := r.MaskReplacement
		if repl == "" {
			repl = "[REDACTED]"
		}
		result = r.Pattern.ReplaceAllString(result, repl)
	}
	return result
}

// maskGeminiWebBody handles URL-encoded form bodies used by the Gemini browser UI.
// The f.req parameter contains nested JSON; we URL-decode it, mask string values,
// and re-encode before returning.
func maskGeminiWebBody(body []byte) []byte {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		log.Printf("[mask] Gemini-Web: url.ParseQuery failed: %v", err)
		return body
	}
	fReq := values.Get("f.req")
	if fReq == "" {
		log.Printf("[mask] Gemini-Web: no f.req param found; body_prefix=%q", truncBody(body, 120))
		return body
	}
	log.Printf("[mask] Gemini-Web: f.req len=%d prefix=%q", len(fReq), truncBody([]byte(fReq), 120))
	masked := maskJSONStrings([]byte(fReq))
	changed := !bytes.Equal(masked, []byte(fReq))
	log.Printf("[mask] Gemini-Web: maskJSONStrings changed=%v fReq_before=%d fReq_after=%d", changed, len(fReq), len(masked))
	if !changed {
		return body
	}
	values.Set("f.req", string(masked))
	return []byte(values.Encode())
}

func truncBody(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
