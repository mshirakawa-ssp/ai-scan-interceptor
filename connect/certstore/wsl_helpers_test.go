package certstore

import (
	"strings"
	"testing"
)

// utf16leEncode is a tiny test helper that encodes an ASCII string into
// UTF-16LE bytes (with a BOM).
func utf16leEncode(s string, withBOM bool) []byte {
	var out []byte
	if withBOM {
		out = append(out, 0xFF, 0xFE)
	}
	for _, r := range s {
		out = append(out, byte(r), 0x00)
	}
	return out
}

func TestDecodeUTF16LE_BOMAndAscii(t *testing.T) {
	got, err := decodeUTF16LE(utf16leEncode("hello", true))
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestDecodeUTF16LE_NoBOM(t *testing.T) {
	got, err := decodeUTF16LE(utf16leEncode("Ubuntu", false))
	if err != nil {
		t.Fatal(err)
	}
	if got != "Ubuntu" {
		t.Errorf("got %q, want %q", got, "Ubuntu")
	}
}

func TestDecodeUTF16LE_OddBytesError(t *testing.T) {
	if _, err := decodeUTF16LE([]byte{0xFF, 0xFE, 0x41}); err == nil {
		t.Fatal("expected error for odd byte count")
	}
}

func TestParseWslList_FiltersDockerAndEmpty(t *testing.T) {
	// Simulate `wsl -l -q` output:
	//   Ubuntu-22.04
	//   Debian
	//   docker-desktop
	//   docker-desktop-data
	//   <blank>
	raw := utf16leEncode("Ubuntu-22.04\r\nDebian\r\ndocker-desktop\r\ndocker-desktop-data\r\n\r\n", true)
	got, err := parseWslList(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Ubuntu-22.04", "Debian"}
	if !sliceEq(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestClassifyOSRelease(t *testing.T) {
	cases := []struct {
		name string
		body string
		want DistroFamily
	}{
		{"ubuntu", `ID=ubuntu` + "\n" + `ID_LIKE=debian`, FamilyDebian},
		{"debian", `ID=debian`, FamilyDebian},
		{"fedora", `ID=fedora`, FamilyRHEL},
		{"rocky", `ID=rocky`, FamilyRHEL},
		{"oracle", `ID="ol"` + "\n" + `ID_LIKE="fedora"`, FamilyRHEL},
		{"id_like_only", `ID=somethingweird` + "\n" + `ID_LIKE="rhel fedora"`, FamilyRHEL},
		{"alpine", `ID=alpine`, FamilyUnknown},
		{"empty", ``, FamilyUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyOSRelease(c.body); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestBuildWSLInstallScript_ContainsRequired(t *testing.T) {
	script := BuildWSLInstallScript("127.0.0.1:8443",
		"# >>> ai-scan-connect managed block (DO NOT EDIT) v1 >>>",
		"# <<< ai-scan-connect managed block <<<")
	for _, want := range []string{
		"AISCAN_CA_PATH",
		"update-ca-certificates",
		"update-ca-trust",
		"/usr/local/share/ca-certificates/aiscan.crt",
		"/etc/pki/ca-trust/source/anchors/aiscan.pem",
		"/etc/profile.d/aiscan.sh",
		"http://127.0.0.1:8443",
		"# >>> ai-scan-connect managed block (DO NOT EDIT) v1 >>>",
		"# <<< ai-scan-connect managed block <<<",
		"getent passwd",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q", want)
		}
	}
}
