package envvars

import "strings"

// Pure helpers for the Windows backend, in a non-tagged file so they can be
// unit-tested on Linux CI.

// stripURLScheme strips "http://" / "https://" prefixes and any trailing
// slash so the output is "host:port" — the form WinINet/WinHTTP expect.
func stripURLScheme(u string) string {
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(u, p) {
			u = u[len(p):]
			break
		}
	}
	return strings.TrimRight(u, "/")
}

// managedEnvNames is the canonical list of variable names Connect controls.
// Exposed as a function (vs. var) so tests can compare against a stable copy.
func managedEnvNames() []string {
	return []string{
		"HTTPS_PROXY",
		"HTTP_PROXY",
		"NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE",
		"SSL_CERT_FILE",
	}
}

// varsToEnvPairs is a pure mapping from Vars to the (name -> value) pairs
// Connect writes. Empty values are dropped.
func varsToEnvPairs(v Vars) map[string]string {
	out := map[string]string{}
	if v.HTTPSProxy != "" {
		out["HTTPS_PROXY"] = v.HTTPSProxy
	}
	if v.HTTPProxy != "" {
		out["HTTP_PROXY"] = v.HTTPProxy
	}
	if v.NodeExtraCACerts != "" {
		out["NODE_EXTRA_CA_CERTS"] = v.NodeExtraCACerts
	}
	if v.RequestsCABundle != "" {
		out["REQUESTS_CA_BUNDLE"] = v.RequestsCABundle
	}
	if v.SSLCertFile != "" {
		out["SSL_CERT_FILE"] = v.SSLCertFile
	}
	return out
}
