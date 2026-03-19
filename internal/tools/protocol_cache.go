package tools

import (
	"sync"
	"time"
)

const protocolCacheTTL = 5 * time.Minute

type protocolEntry struct {
	cachedAt time.Time
}

// protocolCache remembers hosts that only support HTTP/1.1.
// Entries expire after protocolCacheTTL so transient failures don't stick forever.
var protocolCache sync.Map // map[string]protocolEntry

// markHTTP1Only records that a host doesn't support HTTP/2.
func markHTTP1Only(host string) {
	protocolCache.Store(host, protocolEntry{cachedAt: time.Now()})
}

// isHTTP1Only checks if a host is known to only support HTTP/1.1.
// Returns false if the entry has expired.
func isHTTP1Only(host string) bool {
	v, ok := protocolCache.Load(host)
	if !ok {
		return false
	}
	entry := v.(protocolEntry)
	if time.Since(entry.cachedAt) > protocolCacheTTL {
		protocolCache.Delete(host)
		return false
	}
	return true
}
