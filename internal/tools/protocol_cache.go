package tools

import "sync"

// protocolCache remembers hosts that only support HTTP/1.1.
// When HTTP/2 fails and falls back to HTTP/1.1, the host is cached
// so subsequent requests skip the failed HTTP/2 attempt (saves ~15s).
var protocolCache sync.Map // map[string]bool (host -> true means HTTP/1.1 only)

// markHTTP1Only records that a host doesn't support HTTP/2.
func markHTTP1Only(host string) {
	protocolCache.Store(host, true)
}

// isHTTP1Only checks if a host is known to only support HTTP/1.1.
func isHTTP1Only(host string) bool {
	_, ok := protocolCache.Load(host)
	return ok
}
