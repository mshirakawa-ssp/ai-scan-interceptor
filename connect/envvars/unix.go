//go:build !windows

package envvars

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// MarkerStart / MarkerEnd are kept for backward compatibility. The canonical
// constants now live in markers.go (MarkerStartLine / MarkerEndLine) so that
// Windows-only code can reach them too.
const (
	MarkerStart = MarkerStartLine
	MarkerEnd   = MarkerEndLine
)

// blockRegexp matches a previously-written managed block (multiline, lazy).
// We anchor on the exact start marker and the exact end marker. The (?s) flag
// lets `.` match newlines. We also consume the trailing newline after the end
// marker so successive Apply calls don't accumulate blank lines.
var blockRegexp = regexp.MustCompile(`(?s)` +
	regexp.QuoteMeta(MarkerStart) +
	`.*?` +
	regexp.QuoteMeta(MarkerEnd) +
	`\n?`)

type unixManager struct{}

func newManager() Manager { return &unixManager{} }

// rcCandidates returns the list of rc files to touch.
//
// We target the invoking user's shell rc files. When run as root via sudo
// we honor SUDO_USER so the install affects the real user, not /root/.
func rcCandidates() ([]string, error) {
	homeDir, err := resolveHome()
	if err != nil {
		return nil, err
	}
	names := []string{".bashrc", ".zshrc", ".profile"}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, filepath.Join(homeDir, n))
	}
	return out, nil
}

func resolveHome() (string, error) {
	if su := os.Getenv("SUDO_USER"); su != "" {
		u, err := user.Lookup(su)
		if err == nil && u.HomeDir != "" {
			return u.HomeDir, nil
		}
	}
	if h := os.Getenv("HOME"); h != "" {
		return h, nil
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir, nil
	}
	return "", errors.New("envvars: cannot resolve user home dir")
}

// renderBlock returns the managed-block text (including markers, with
// trailing newline).
func renderBlock(v Vars) string {
	var b strings.Builder
	b.WriteString(MarkerStart)
	b.WriteByte('\n')
	fmt.Fprintf(&b, "# generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	if v.HTTPSProxy != "" {
		fmt.Fprintf(&b, "export HTTPS_PROXY=%s\n", shellQuote(v.HTTPSProxy))
		fmt.Fprintf(&b, "export https_proxy=%s\n", shellQuote(v.HTTPSProxy))
	}
	if v.HTTPProxy != "" {
		fmt.Fprintf(&b, "export HTTP_PROXY=%s\n", shellQuote(v.HTTPProxy))
		fmt.Fprintf(&b, "export http_proxy=%s\n", shellQuote(v.HTTPProxy))
	}
	if v.NodeExtraCACerts != "" {
		fmt.Fprintf(&b, "export NODE_EXTRA_CA_CERTS=%s\n", shellQuote(v.NodeExtraCACerts))
	}
	if v.RequestsCABundle != "" {
		fmt.Fprintf(&b, "export REQUESTS_CA_BUNDLE=%s\n", shellQuote(v.RequestsCABundle))
	}
	if v.SSLCertFile != "" {
		fmt.Fprintf(&b, "export SSL_CERT_FILE=%s\n", shellQuote(v.SSLCertFile))
	}
	b.WriteString(MarkerEnd)
	b.WriteByte('\n')
	return b.String()
}

// shellQuote returns a POSIX-shell-safe single-quoted form.
func shellQuote(s string) string {
	// Replace ' with '\'' (close, escape, reopen).
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// stripBlock removes any previously-written managed block from src.
func stripBlock(src string) string {
	out := blockRegexp.ReplaceAllString(src, "")
	// Also collapse a leading newline if we ate one in the middle.
	return out
}

// rewriteFile reads path, strips any old managed block, optionally appends
// newBlock (skipped if empty), and writes back atomically (best-effort).
//
// Returns true if the file was modified.
func rewriteFile(path string, newBlock string, mustExist bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !mustExist {
			// Skip non-existent rc files silently — common, e.g. no .zshrc.
			return false, nil
		}
		return false, err
	}
	orig := string(data)
	stripped := stripBlock(orig)

	var next string
	if newBlock == "" {
		next = stripped
	} else {
		// Ensure the file ends with a newline before appending.
		if len(stripped) > 0 && !strings.HasSuffix(stripped, "\n") {
			stripped += "\n"
		}
		next = stripped + "\n" + newBlock
	}

	if next == orig {
		return false, nil
	}
	// Best-effort atomic write: write to a sibling tmp, then rename.
	tmp := path + ".aiscan.tmp"
	if err := os.WriteFile(tmp, []byte(next), 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

func (u *unixManager) Apply(v Vars) ([]string, error) {
	candidates, err := rcCandidates()
	if err != nil {
		return nil, err
	}
	block := renderBlock(v)
	var touched []string
	var errs []error
	for _, p := range candidates {
		// Only rewrite files that already exist; we don't create rc files.
		if _, err := os.Stat(p); err != nil {
			continue
		}
		changed, err := rewriteFile(p, block, true)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		if changed {
			touched = append(touched, p)
		}
	}
	return touched, errors.Join(errs...)
}

func (u *unixManager) Remove() ([]string, error) {
	candidates, err := rcCandidates()
	if err != nil {
		return nil, err
	}
	var touched []string
	var errs []error
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		changed, err := rewriteFile(p, "", true)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		if changed {
			touched = append(touched, p)
		}
	}
	return touched, errors.Join(errs...)
}

func (u *unixManager) CheckIntegrity(v Vars) ([]string, error) {
	candidates, err := rcCandidates()
	if err != nil {
		return nil, err
	}
	expected := renderBlock(v)
	// Strip the "generated:" timestamp from comparison — only structural drift matters.
	expectedNoTS := stripGenLine(expected)

	var drift []string
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		m := blockRegexp.FindString(string(data))
		if m == "" {
			drift = append(drift, p)
			continue
		}
		if stripGenLine(m) != expectedNoTS {
			drift = append(drift, p)
		}
	}
	return drift, nil
}

var genLineRegexp = regexp.MustCompile(`(?m)^# generated: .*\n`)

func stripGenLine(s string) string {
	return genLineRegexp.ReplaceAllString(s, "")
}
