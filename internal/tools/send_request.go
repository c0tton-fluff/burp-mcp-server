package tools

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// http2Timeout is a shorter timeout for the HTTP/2 attempt so fallback is fast.
const http2Timeout = 15 * time.Second

// SendRequestInput is the input for the burp_send_request tool.
type SendRequestInput struct {
	// Raw HTTP request (request line + headers + body)
	Raw string `json:"raw" jsonschema:"required,Raw HTTP request including headers and body"`
	// Target host (overrides Host header)
	Host string `json:"host,omitempty" jsonschema:"Target host (overrides Host header)"`
	// Target port
	Port int `json:"port,omitempty" jsonschema:"Target port (default based on TLS)"`
	// Use HTTPS
	TLS *bool `json:"tls,omitempty" jsonschema:"Use HTTPS (default true)"`
	// Body limit in bytes (default 2000)
	BodyLimit int `json:"bodyLimit,omitempty" jsonschema:"Response body byte limit (default 2000)"`
	// Body offset in bytes
	BodyOffset int `json:"bodyOffset,omitempty" jsonschema:"Response body byte offset"`
}

// SendRequestOutput is the clean response from burp_send_request.
type SendRequestOutput struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	BodySize   int               `json:"bodySize"`
	Truncated  bool              `json:"truncated,omitempty"`
}

func sendRequestHandler(session *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, SendRequestInput) (*mcp.CallToolResult, SendRequestOutput, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input SendRequestInput) (*mcp.CallToolResult, SendRequestOutput, error) {
		if input.Raw == "" {
			return nil, SendRequestOutput{}, fmt.Errorf("raw HTTP request is required")
		}

		parsed := burp.ParseRawRequest(input.Raw)

		// Determine host
		host := input.Host
		if host == "" {
			host = parsed.Host
		}
		if host == "" {
			return nil, SendRequestOutput{}, fmt.Errorf("host is required (provide in input or Host header)")
		}

		// Parse host:port (supports IPv6 like [::1]:8080)
		if h, p, err := net.SplitHostPort(host); err == nil {
			host = h
			if input.Port == 0 {
				if pn, err := strconv.Atoi(p); err == nil {
					input.Port = pn
				}
			}
		}

		// Determine TLS
		useTLS := true
		if input.TLS != nil {
			useTLS = *input.TLS
		}

		// Determine port
		port := input.Port
		if port == 0 {
			if useTLS {
				port = 443
			} else {
				port = 80
			}
		}

		// Body limit defaults
		bodyLimit := input.BodyLimit
		if bodyLimit == 0 {
			bodyLimit = 2000
		}

		// Normalize raw request line endings for Burp
		rawNorm := normalizeRawRequest(input.Raw)

		// Try HTTP/2 first, then fall back to HTTP/1.1
		responseText, err := tryHTTP2(ctx, session, parsed, host, port, useTLS)
		if err != nil {
			// Fall back to HTTP/1.1
			responseText, err = tryHTTP1(ctx, session, rawNorm, host, port, useTLS)
			if err != nil {
				return nil, SendRequestOutput{}, fmt.Errorf("request failed: %w", err)
			}
		}

		// Unwrap Burp's HttpRequestResponse{...} wrapper, extract just the HTTP response
		responseText = burp.UnwrapResponse(responseText)

		// Fall back to HTTP/1.1 if HTTP/2 response is empty or 502
		needsFallback := strings.TrimSpace(responseText) == ""
		if !needsFallback && strings.HasPrefix(responseText, "HTTP/") {
			parts := strings.SplitN(responseText, " ", 3)
			needsFallback = len(parts) >= 2 && parts[1] == "502"
		}
		if needsFallback {
			fallbackText, fallbackErr := tryHTTP1(ctx, session, rawNorm, host, port, useTLS)
			if fallbackErr == nil {
				responseText = burp.UnwrapResponse(fallbackText)
			}
		}

		// Parse the response
		resp := burp.ParseHTTPResponse(responseText, input.BodyOffset, bodyLimit)
		if resp == nil {
			return nil, SendRequestOutput{}, fmt.Errorf("failed to parse response")
		}

		output := SendRequestOutput{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       resp.Body,
			BodySize:   resp.BodySize,
			Truncated:  resp.Truncated,
		}

		return nil, output, nil
	}
}

// tryHTTP2 sends the request via HTTP/2 using Burp's send_http2_request tool.
func tryHTTP2(ctx context.Context, session *mcp.ClientSession, parsed *burp.ParsedHTTPRequest, host string, port int, tls bool) (string, error) {
	// Build pseudo-headers
	scheme := "https"
	if !tls {
		scheme = "http"
	}

	pseudoHeaders := map[string]any{
		":method":    parsed.Method,
		":path":      parsed.Path,
		":authority": host,
		":scheme":    scheme,
	}

	// Build regular headers (exclude Host since :authority covers it)
	headers := make(map[string]any)
	for k, v := range parsed.Headers {
		if !strings.EqualFold(k, "host") {
			headers[k] = v
		}
	}

	args := map[string]any{
		"pseudoHeaders":  pseudoHeaders,
		"headers":        headers,
		"requestBody":    parsed.Body,
		"targetHostname": host,
		"targetPort":     port,
		"usesHttps":      tls,
	}

	return burp.CallToolWithTimeout(ctx, session, "send_http2_request", args, http2Timeout)
}

// tryHTTP1 sends the request via HTTP/1.1 using Burp's send_http1_request tool.
func tryHTTP1(ctx context.Context, session *mcp.ClientSession, rawContent string, host string, port int, tls bool) (string, error) {
	args := map[string]any{
		"content":        rawContent,
		"targetHostname": host,
		"targetPort":     port,
		"usesHttps":      tls,
	}

	return burp.CallTool(ctx, session, "send_http1_request", args)
}

// RegisterSendRequestTool registers the burp_send_request tool.
func RegisterSendRequestTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_send_request",
		Description: `Send HTTP request via Burp. Auto-detects HTTP/2 vs HTTP/1.1. Takes raw HTTP request string. Returns {statusCode, headers, body, bodySize, truncated}. Body limit: 2KB default.`,
	}, sendRequestHandler(session))
}
