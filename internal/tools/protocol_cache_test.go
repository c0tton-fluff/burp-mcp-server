package tools

import (
	"testing"
	"time"
)

func TestProtocolCache_MarkAndCheck(t *testing.T) {
	host := "test-cache-mark.example.com"
	if isHTTP1Only(host) {
		t.Error("should not be cached initially")
	}
	markHTTP1Only(host)
	if !isHTTP1Only(host) {
		t.Error("should be cached after marking")
	}
}

func TestProtocolCache_Expiry(t *testing.T) {
	host := "test-cache-expiry.example.com"

	// Manually store an expired entry
	protocolCache.Store(host, protocolEntry{
		cachedAt: time.Now().Add(-protocolCacheTTL - time.Second),
	})

	if isHTTP1Only(host) {
		t.Error("expired entry should return false")
	}

	// Entry should be cleaned up
	if _, ok := protocolCache.Load(host); ok {
		t.Error("expired entry should be deleted")
	}
}

func TestProtocolCache_Unknown(t *testing.T) {
	if isHTTP1Only("never-seen.example.com") {
		t.Error("unknown host should not be cached")
	}
}
