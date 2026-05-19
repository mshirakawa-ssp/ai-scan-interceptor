//go:build !windows

package envvars

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderBlock_ContainsExpectedExports(t *testing.T) {
	v := Vars{
		HTTPSProxy:       "http://127.0.0.1:8443",
		HTTPProxy:        "http://127.0.0.1:8443",
		NodeExtraCACerts: "/etc/ssl/certs/aiscan.pem",
	}
	out := renderBlock(v)
	for _, want := range []string{
		MarkerStart,
		MarkerEnd,
		"export HTTPS_PROXY='http://127.0.0.1:8443'",
		"export HTTP_PROXY='http://127.0.0.1:8443'",
		"export NODE_EXTRA_CA_CERTS='/etc/ssl/certs/aiscan.pem'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("renderBlock missing %q\n--- got:\n%s", want, out)
		}
	}
}

func TestStripBlock_RemovesPreviouslyWritten(t *testing.T) {
	prefix := "# user prefix line\nexport FOO=bar\n"
	suffix := "\n# user suffix line\n"
	v := Vars{HTTPSProxy: "http://x"}
	block := renderBlock(v)
	full := prefix + block + suffix

	stripped := stripBlock(full)
	if strings.Contains(stripped, MarkerStart) || strings.Contains(stripped, MarkerEnd) {
		t.Fatalf("markers not stripped:\n%s", stripped)
	}
	if !strings.Contains(stripped, "export FOO=bar") {
		t.Fatalf("user content lost:\n%s", stripped)
	}
}

func TestApplyAndRemove_Idempotent(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("SUDO_USER", "")

	rc := filepath.Join(tmpHome, ".bashrc")
	original := "# user content\nexport USER_VAR=1\n"
	if err := os.WriteFile(rc, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	mgr := New()
	v := Vars{
		HTTPSProxy:       "http://127.0.0.1:8443",
		NodeExtraCACerts: "/etc/ssl/certs/aiscan.pem",
	}

	// Apply twice — second time must not duplicate the block.
	if _, err := mgr.Apply(v); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	if _, err := mgr.Apply(v); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}

	data, _ := os.ReadFile(rc)
	if c := strings.Count(string(data), MarkerStart); c != 1 {
		t.Fatalf("expected exactly 1 managed block, got %d:\n%s", c, string(data))
	}
	if !strings.Contains(string(data), "export USER_VAR=1") {
		t.Fatalf("user content lost:\n%s", string(data))
	}

	// CheckIntegrity should report no drift after Apply.
	drift, err := mgr.CheckIntegrity(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 0 {
		t.Errorf("unexpected drift: %v", drift)
	}

	// Now remove — managed block gone, user content survives.
	if _, err := mgr.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	data, _ = os.ReadFile(rc)
	if strings.Contains(string(data), MarkerStart) {
		t.Fatalf("Remove left marker:\n%s", string(data))
	}
	if !strings.Contains(string(data), "export USER_VAR=1") {
		t.Fatalf("Remove ate user content:\n%s", string(data))
	}
}

func TestCheckIntegrity_DetectsMissing(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("SUDO_USER", "")

	rc := filepath.Join(tmpHome, ".bashrc")
	if err := os.WriteFile(rc, []byte("# nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr := New()
	drift, err := mgr.CheckIntegrity(Vars{HTTPSProxy: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 1 || drift[0] != rc {
		t.Errorf("drift = %v, want [%s]", drift, rc)
	}
}
