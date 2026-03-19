package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// http2Timeout is a shorter timeout for the HTTP/2 attempt so fallback is fast.
const http2Timeout = 15 * time.Second

// SendRequestInput is the input for the burp_send_request tool.
type SendRequestInput struct {
	Raw         string `json:"raw" jsonschema:"required,Raw HTTP request including headers and body"`
	Host        string `json:"host,omitempty" jsonschema:"Target host (overrides Host header)"`
	Port        int    `json:"port,omitempty" jsonschema:"Target port (default based on TLS)"`
	TLS         *bool  `json:"tls,omitempty" jsonschema:"Use HTTPS (default true)"`
	BodyLimit   int    `json:"bodyLimit,omitempty" jsonschema:"Response body byte limit (default 10000)"`
	BodyOffset  int    `json:"bodyOffset,omitempty" jsonschema:"Response body byte offset"`
	AllHeaders  bool   `json:"allHeaders,omitempty" jsonschema:"Return all headers (default: security-relevant only)"`
	HeadersOnly bool   `json:"headersOnly,omitempty" jsonschema:"Return only status and headers, skip body"`
}

// defaultBodyLimit is the default response body byte limit across tools.
const defaultBodyLimit = 10000

// SendRequestOutput is the clean response from burp_send_request.
type SendRequestOutput struct {
	StatusCode int            `json:"statusCode"`
	Headers    map[string]any `json:"headers,omitempty"`
	Body       string         `json:"body,omitempty"`
	BodySize   int            `json:"bodySize"`
	Truncated  bool           `json:"truncated,omitempty"`
}

func sendRequestHandler(client *burp.Client) func(context.Context, *mcp.CallToolRequest, SendRequestInput) (*mcp.CallToolResult, SendRequestOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input SendRequestInput) (*mcp.CallToolResult, SendRequestOutput, error) {
		if err := validateRawRequest(input.Raw); err != nil {
			return nil, SendRequestOutput{}, err
		}

		parsed := burp.ParseRawRequest(input.Raw)

		t, err := resolveTarget(input.Host, input.Port, input.TLS, parsed.Host)
		if err != nil {
			return nil, SendRequestOutput{}, err
		}

		rawNorm := normalizeRawRequest(input.Raw)
		responseText, err := sendWithFallback(ctx, client, rawNorm, parsed, t)
		if err != nil {
			return nil, SendRequestOutput{}, err
		}

		bodyLimit := input.BodyLimit
		if bodyLimit == 0 {
			bodyLimit = defaultBodyLimit
		}
		parseLimit := bodyLimit
		if input.HeadersOnly {
			parseLimit = 1
		}

		resp := burp.ParseHTTPResponse(responseText, input.BodyOffset, parseLimit)
		if resp == nil {
			return nil, SendRequestOutput{}, fmt.Errorf("failed to parse response")
		}

		headers := resp.Headers
		if !input.AllHeaders {
			headers = burp.FilterHeaders(headers)
		}

		output := SendRequestOutput{
			StatusCode: resp.StatusCode,
			Headers:    burp.FlattenHeaders(headers),
			BodySize:   resp.BodySize,
		}
		if !input.HeadersOnly {
			output.Body = resp.Body
			output.Truncated = resp.Truncated
		}

		return nil, output, nil
	}
}

// tryHTTP2 sends the request via HTTP/2 using Burp's send_http2_request tool.
func tryHTTP2(ctx context.Context, client *burp.Client, parsed *burp.ParsedHTTPRequest, host string, port int, tls bool) (string, error) {
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

	headers := make(map[string]any)
	for k, vals := range parsed.Headers {
		if k != "Host" && k != "host" {
			if len(vals) == 1 {
				headers[k] = vals[0]
			} else {
				headers[k] = vals
			}
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

	return client.CallToolWithTimeout(ctx, "send_http2_request", args, http2Timeout)
}

// tryHTTP1 sends the request via HTTP/1.1 using Burp's send_http1_request tool.
func tryHTTP1(ctx context.Context, client *burp.Client, rawContent string, host string, port int, tls bool) (string, error) {
	args := map[string]any{
		"content":        rawContent,
		"targetHostname": host,
		"targetPort":     port,
		"usesHttps":      tls,
	}

	return client.CallTool(ctx, "send_http1_request", args)
}

// RegisterSendRequestTool registers the burp_send_request tool.
func RegisterSendRequestTool(server *mcp.Server, client *burp.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_send_request",
		Description: `Send HTTP request via Burp. Returns {statusCode, headers, body, bodySize, truncated}. Default: security headers only, 10KB body. Options: allHeaders, headersOnly, bodyLimit, bodyOffset.`,
	}, sendRequestHandler(client))
}
