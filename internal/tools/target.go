package tools

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
)

// maxRawRequestSize caps the raw HTTP request input to prevent memory abuse.
const maxRawRequestSize = 1 << 20 // 1 MB

// resolvedTarget holds the resolved host, port, and TLS settings.
type resolvedTarget struct {
	Host   string
	Port   int
	UseTLS bool
}

// resolveTarget determines host, port, and TLS from user input and parsed request.
// hostOverride and portOverride come from the tool input; parsedHost from the Host header.
func resolveTarget(hostOverride string, portOverride int, tlsFlag *bool, parsedHost string) (resolvedTarget, error) {
	host := hostOverride
	if host == "" {
		host = parsedHost
	}
	if host == "" {
		return resolvedTarget{}, fmt.Errorf("host is required (provide in input or Host header)")
	}

	port := portOverride
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if port == 0 {
			if pn, err := strconv.Atoi(p); err == nil {
				port = pn
			}
		}
	}

	useTLS := true
	if tlsFlag != nil {
		useTLS = *tlsFlag
	}

	if port == 0 {
		if useTLS {
			port = 443
		} else {
			port = 80
		}
	}

	return resolvedTarget{Host: host, Port: port, UseTLS: useTLS}, nil
}

// sendWithFallback sends an HTTP request with HTTP/2 -> HTTP/1.1 fallback.
// Returns the unwrapped response text or an error.
func sendWithFallback(ctx context.Context, client *burp.Client, rawNorm string, parsed *burp.ParsedHTTPRequest, t resolvedTarget) (string, error) {
	if isHTTP1Only(t.Host) {
		text, err := tryHTTP1(ctx, client, rawNorm, t.Host, t.Port, t.UseTLS)
		if err != nil {
			return "", fmt.Errorf("request failed: %w", err)
		}
		return burp.UnwrapResponse(text), nil
	}

	text, err := tryHTTP2(ctx, client, parsed, t.Host, t.Port, t.UseTLS)
	if err != nil {
		markHTTP1Only(t.Host)
		text, err = tryHTTP1(ctx, client, rawNorm, t.Host, t.Port, t.UseTLS)
		if err != nil {
			return "", fmt.Errorf("request failed: %w", err)
		}
	}

	text = burp.UnwrapResponse(text)

	needsFallback := strings.TrimSpace(text) == ""
	if !needsFallback && strings.HasPrefix(text, "HTTP/") {
		parts := strings.SplitN(text, " ", 3)
		needsFallback = len(parts) >= 2 && parts[1] == "502"
	}
	if needsFallback {
		markHTTP1Only(t.Host)
		fb, fbErr := tryHTTP1(ctx, client, rawNorm, t.Host, t.Port, t.UseTLS)
		if fbErr == nil {
			text = burp.UnwrapResponse(fb)
		}
	}

	return text, nil
}

// validateRawRequest checks the raw request input is non-empty and within size limits.
func validateRawRequest(raw string) error {
	if raw == "" {
		return fmt.Errorf("raw HTTP request is required")
	}
	if len(raw) > maxRawRequestSize {
		return fmt.Errorf("raw request too large (%d bytes, max %d)", len(raw), maxRawRequestSize)
	}
	return nil
}
