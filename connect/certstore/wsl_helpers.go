package certstore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// WSL helpers — pure logic, no syscalls. Lives in a non-tagged file so we can
// test the UTF-16LE decoder, distro filter, and script template on Linux CI.

// decodeUTF16LE decodes a UTF-16LE byte stream to a UTF-8 string. A leading
// BOM (FF FE) is stripped if present. An odd-length input returns an error.
func decodeUTF16LE(b []byte) (string, error) {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		b = b[2:]
	}
	if len(b)%2 != 0 {
		return "", errors.New("decodeUTF16LE: odd byte count")
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16)), nil
}

// parseWslList parses the output of `wsl.exe -l -q` (UTF-16LE) and returns
// the filtered list of distro names suitable for installation.
//
// Filters out:
//   - empty / whitespace-only lines
//   - "docker-desktop" / "docker-desktop-data" (Docker Desktop's WSL2 backing)
//   - any line containing a NUL (defensive against trailing decode artifacts)
func parseWslList(raw []byte) ([]string, error) {
	s, err := decodeUTF16LE(raw)
	if err != nil {
		return nil, err
	}
	// Normalize CRLF.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\x00"))
		if line == "" {
			continue
		}
		if strings.Contains(line, "\x00") {
			continue
		}
		switch line {
		case "docker-desktop", "docker-desktop-data":
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// DistroFamily classifies a WSL distro into a supported package family.
type DistroFamily int

const (
	FamilyUnknown DistroFamily = iota
	FamilyDebian               // debian, ubuntu, ...
	FamilyRHEL                 // rhel, centos, fedora, rocky, almalinux, ol
)

// classifyOSRelease parses an /etc/os-release file body and returns the
// supported family. ID_LIKE is consulted when ID itself is unrecognized.
func classifyOSRelease(body string) DistroFamily {
	id, idLike := readOSReleaseID(body)
	switch id {
	case "debian", "ubuntu", "linuxmint", "pop", "elementary", "kali", "raspbian":
		return FamilyDebian
	case "rhel", "centos", "fedora", "rocky", "almalinux", "ol":
		return FamilyRHEL
	}
	for _, x := range strings.Fields(idLike) {
		switch strings.Trim(x, `"`) {
		case "debian", "ubuntu":
			return FamilyDebian
		case "rhel", "fedora", "centos":
			return FamilyRHEL
		}
	}
	return FamilyUnknown
}

func readOSReleaseID(body string) (id, idLike string) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		} else if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		}
	}
	return
}

// BuildWSLInstallScript returns the shell script to be piped into
// `wsl -d <distro> -u root -- /bin/sh`. The script:
//
//  1. detects family via /etc/os-release
//  2. writes the org CA to the right anchor dir
//  3. refreshes the OS trust store
//  4. drops a /etc/profile.d/aiscan.sh with HTTPS_PROXY + NODE_EXTRA_CA_CERTS
//  5. writes the same managed block into each interactive user's rc files
//
// Inputs:
//   - listenAddr: e.g. "127.0.0.1:8443" — Connect's local listen on the WSL host network
//   - markerStart / markerEnd: the same markers envvars/unix.go uses
//
// pemBytes is delivered out-of-band (via stdin / temp file); the script
// reads it from $AISCAN_CA_PATH which the caller exports before invoking sh.
func BuildWSLInstallScript(listenAddr, markerStart, markerEnd string) string {
	// Note: the script intentionally uses "set -e" sparingly so that one failed
	// per-user rc-write doesn't abort the whole distro install.
	// Marker-start/end must be embedded literally; we wrap them in single-quoted
	// heredoc-safe form. Since the markers are pure ASCII comments, they're
	// safe inside a 'EOF' heredoc with no expansion.
	return fmt.Sprintf(`#!/bin/sh
set -u

if [ -z "${AISCAN_CA_PATH:-}" ] || [ ! -r "$AISCAN_CA_PATH" ]; then
  echo "aiscan: AISCAN_CA_PATH not set or not readable" >&2
  exit 2
fi

ID=""
ID_LIKE=""
if [ -r /etc/os-release ]; then
  . /etc/os-release
fi

family=""
case "$ID" in
  debian|ubuntu|linuxmint|pop|elementary|kali|raspbian) family=debian ;;
  rhel|centos|fedora|rocky|almalinux|ol) family=rhel ;;
  *) for x in $ID_LIKE; do
       case "$x" in
         debian|ubuntu) family=debian ;;
         rhel|fedora|centos) family=rhel ;;
       esac
     done ;;
esac

if [ -z "$family" ]; then
  echo "aiscan: unsupported distro ID=$ID — skipping CA install" >&2
  exit 0
fi

if [ "$family" = "debian" ]; then
  install -d -m 0755 /usr/local/share/ca-certificates
  install -m 0644 "$AISCAN_CA_PATH" /usr/local/share/ca-certificates/aiscan.crt
  update-ca-certificates >/dev/null 2>&1 || true
elif [ "$family" = "rhel" ]; then
  install -d -m 0755 /etc/pki/ca-trust/source/anchors
  install -m 0644 "$AISCAN_CA_PATH" /etc/pki/ca-trust/source/anchors/aiscan.pem
  update-ca-trust extract >/dev/null 2>&1 || true
fi

# /etc/profile.d/aiscan.sh — applied to all login shells
install -d -m 0755 /etc/profile.d
cat > /etc/profile.d/aiscan.sh <<EOF
export HTTPS_PROXY='http://%s'
export https_proxy='http://%s'
export HTTP_PROXY='http://%s'
export http_proxy='http://%s'
export NODE_EXTRA_CA_CERTS='/etc/ssl/certs/aiscan.pem'
export REQUESTS_CA_BUNDLE='/etc/ssl/certs/aiscan.pem'
export SSL_CERT_FILE='/etc/ssl/certs/aiscan.pem'
EOF
chmod 0644 /etc/profile.d/aiscan.sh

# Also stage the bundle at /etc/ssl/certs/aiscan.pem regardless of family
install -d -m 0755 /etc/ssl/certs
install -m 0644 "$AISCAN_CA_PATH" /etc/ssl/certs/aiscan.pem

# Per-user rc file managed block (UID >= 1000)
getent passwd | awk -F: '$3 >= 1000 && $7 !~ /(false|nologin)/ { print $6 }' | while read -r home; do
  [ -d "$home" ] || continue
  for rc in .bashrc .zshrc .profile; do
    f="$home/$rc"
    [ -f "$f" ] || continue
    # Strip any previous managed block (idempotent), then append.
    awk -v s='%s' -v e='%s' '
      $0 == s { skip=1; next }
      $0 == e { skip=0; next }
      skip != 1 { print }
    ' "$f" > "$f.aiscan.tmp" && mv "$f.aiscan.tmp" "$f"
    {
      echo ""
      echo '%s'
      echo "# generated by ai-scan-connect (WSL)"
      echo "export HTTPS_PROXY='http://%s'"
      echo "export https_proxy='http://%s'"
      echo "export HTTP_PROXY='http://%s'"
      echo "export http_proxy='http://%s'"
      echo "export NODE_EXTRA_CA_CERTS='/etc/ssl/certs/aiscan.pem'"
      echo "export REQUESTS_CA_BUNDLE='/etc/ssl/certs/aiscan.pem'"
      echo "export SSL_CERT_FILE='/etc/ssl/certs/aiscan.pem'"
      echo '%s'
    } >> "$f"
    chown --reference="$home" "$f" 2>/dev/null || true
  done
done

echo "aiscan: WSL install OK (family=$family)"
`,
		listenAddr, listenAddr, listenAddr, listenAddr, // /etc/profile.d block
		markerStart, markerEnd, // awk strip
		markerStart,                                                     // append start
		listenAddr, listenAddr, listenAddr, listenAddr, // appended export lines
		markerEnd, // append end
	)
}
