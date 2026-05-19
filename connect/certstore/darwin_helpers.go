package certstore

// macOS argument-builder helpers. Pure / no syscalls — placed in a
// non-tagged file so they can be unit-tested on Linux CI as well.

// SystemKeychain is the standard System keychain path used for machine-wide
// trust on macOS.
const SystemKeychain = "/Library/Keychains/System.keychain"

// securityAddTrustedArgs returns args for:
//
//	security add-trusted-cert -d -r trustRoot -k <keychain> <pem-path>
//
// -d: system trust (vs. login keychain)
// -r trustRoot: full root trust (TLS, S/MIME, ...)
func securityAddTrustedArgs(keychain, pemPath string) []string {
	return []string{
		"add-trusted-cert",
		"-d",
		"-r", "trustRoot",
		"-k", keychain,
		pemPath,
	}
}

// securityDeleteByCNArgs returns args for:
//
//	security delete-certificate -c <CN> <keychain>
func securityDeleteByCNArgs(keychain, cn string) []string {
	return []string{
		"delete-certificate",
		"-c", cn,
		keychain,
	}
}

// securityFindByCNArgs returns args for:
//
//	security find-certificate -a -c <CN> -Z <keychain>
//
// -Z prints SHA-1 / SHA-256 lines, useful for fingerprint comparison.
func securityFindByCNArgs(keychain, cn string) []string {
	return []string{
		"find-certificate",
		"-a",
		"-c", cn,
		"-Z",
		keychain,
	}
}
