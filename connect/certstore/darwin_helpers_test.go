package certstore

import "testing"

func TestSecurityAddTrustedArgs(t *testing.T) {
	args := securityAddTrustedArgs("/Library/Keychains/System.keychain", "/tmp/ca.pem")
	want := []string{
		"add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", "/tmp/ca.pem",
	}
	if !sliceEq(args, want) {
		t.Errorf("got %v, want %v", args, want)
	}
}

func TestSecurityDeleteByCNArgs(t *testing.T) {
	args := securityDeleteByCNArgs(SystemKeychain, "acme-ca")
	want := []string{"delete-certificate", "-c", "acme-ca", SystemKeychain}
	if !sliceEq(args, want) {
		t.Errorf("got %v, want %v", args, want)
	}
}

func TestSecurityFindByCNArgs(t *testing.T) {
	args := securityFindByCNArgs(SystemKeychain, "acme-ca")
	want := []string{"find-certificate", "-a", "-c", "acme-ca", "-Z", SystemKeychain}
	if !sliceEq(args, want) {
		t.Errorf("got %v, want %v", args, want)
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
