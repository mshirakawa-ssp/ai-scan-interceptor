package icap

import (
	"net"
	"strings"
	"sync"
	"time"
)

var (
	hostnameCacheMu sync.Mutex
	hostnameCache   = map[string]hostnameCacheEntry{}
)

type hostnameCacheEntry struct {
	name    string
	expires time.Time
}

// lookupHostname resolves a client IP to its short hostname (first DNS label).
// Results are cached for 5 minutes. Returns "" if lookup fails.
func lookupHostname(ip string) string {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return ""
	}

	hostnameCacheMu.Lock()
	if e, ok := hostnameCache[ip]; ok && time.Now().Before(e.expires) {
		hostnameCacheMu.Unlock()
		return e.name
	}
	hostnameCacheMu.Unlock()

	name := ""
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		fqdn := strings.TrimSuffix(names[0], ".")
		if idx := strings.IndexByte(fqdn, '.'); idx > 0 {
			name = fqdn[:idx]
		} else {
			name = fqdn
		}
		// Docker container names (e.g. ai-scan-interceptor-tls-proxy-1) are
		// infrastructure, not user identities — suppress them.
		if strings.Contains(name, "ai-scan-interceptor-") {
			name = ""
		}
	}

	hostnameCacheMu.Lock()
	hostnameCache[ip] = hostnameCacheEntry{name: name, expires: time.Now().Add(5 * time.Minute)}
	hostnameCacheMu.Unlock()
	return name
}
