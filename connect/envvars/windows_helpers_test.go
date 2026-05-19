package envvars

import "testing"

func TestStripURLScheme(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://127.0.0.1:8443", "127.0.0.1:8443"},
		{"https://127.0.0.1:8443/", "127.0.0.1:8443"},
		{"127.0.0.1:8443", "127.0.0.1:8443"},
		{"http://example.com/", "example.com"},
		{"", ""},
	}
	for _, c := range cases {
		if got := stripURLScheme(c.in); got != c.want {
			t.Errorf("stripURLScheme(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVarsToEnvPairs_OnlyNonEmpty(t *testing.T) {
	v := Vars{
		HTTPSProxy:       "http://127.0.0.1:8443",
		NodeExtraCACerts: `C:\ProgramData\AIScanConnect\aiscan.pem`,
		// Others left blank intentionally.
	}
	got := varsToEnvPairs(v)
	if len(got) != 2 {
		t.Fatalf("expected 2 pairs, got %d (%v)", len(got), got)
	}
	if got["HTTPS_PROXY"] != "http://127.0.0.1:8443" {
		t.Errorf("HTTPS_PROXY = %q", got["HTTPS_PROXY"])
	}
	if got["NODE_EXTRA_CA_CERTS"] != `C:\ProgramData\AIScanConnect\aiscan.pem` {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q", got["NODE_EXTRA_CA_CERTS"])
	}
	if _, has := got["HTTP_PROXY"]; has {
		t.Errorf("HTTP_PROXY should not be set")
	}
}

func TestManagedEnvNames_Stable(t *testing.T) {
	got := managedEnvNames()
	want := []string{"HTTPS_PROXY", "HTTP_PROXY", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
