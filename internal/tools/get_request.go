package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetRequestInput is the input for burp_get_request.
type GetRequestInput struct {
	Index      int  `json:"index" jsonschema:"required,Proxy history index (1-based)"`
	BodyLimit  int  `json:"bodyLimit,omitempty" jsonschema:"Response body byte limit (default 10000)"`
	BodyOffset int  `json:"bodyOffset,omitempty" jsonschema:"Response body byte offset"`
	AllHeaders bool `json:"allHeaders,omitempty" jsonschema:"Return all headers (default: security-relevant only)"`
}

// GetRequestOutput is the output of burp_get_request.
type GetRequestOutput struct {
	Request  RequestSummary  `json:"request"`
	Response ResponseSummary `json:"response"`
}

// RequestSummary is the request portion.
type RequestSummary struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Host    string              `json:"host,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    string              `json:"body,omitempty"`
}

// ResponseSummary is the response portion.
type ResponseSummary struct {
	StatusCode int            `json:"statusCode"`
	Headers    map[string]any `json:"headers,omitempty"`
	Body       string         `json:"body,omitempty"`
	BodySize   int            `json:"bodySize"`
	Truncated  bool           `json:"truncated,omitempty"`
}

func getRequestHandler(client *burp.Client) func(context.Context, *mcp.CallToolRequest, GetRequestInput) (*mcp.CallToolResult, GetRequestOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input GetRequestInput) (*mcp.CallToolResult, GetRequestOutput, error) {
		if input.Index < 1 {
			return nil, GetRequestOutput{}, fmt.Errorf("index must be >= 1")
		}

		bodyLimit := input.BodyLimit
		if bodyLimit == 0 {
			bodyLimit = defaultBodyLimit
		}

		args := map[string]any{
			"count":  1,
			"offset": input.Index - 1,
		}

		raw, err := client.CallTool(ctx, "get_proxy_http_history", args)
		if err != nil {
			return nil, GetRequestOutput{}, fmt.Errorf("failed to get request: %w", err)
		}

		if raw == "" {
			return nil, GetRequestOutput{}, fmt.Errorf("no entry at index %d", input.Index)
		}

		reqRaw, respRaw := burp.ExtractRequestResponse(raw)
		parsedReq := burp.ParseRawRequest(reqRaw)

		reqSummary := RequestSummary{
			Method:  parsedReq.Method,
			Path:    parsedReq.Path,
			Host:    parsedReq.Host,
			Headers: parsedReq.Headers,
			Body:    parsedReq.Body,
		}

		parsedResp := burp.ParseHTTPResponse(respRaw, input.BodyOffset, bodyLimit)

		var respSummary ResponseSummary
		if parsedResp != nil {
			headers := parsedResp.Headers
			if !input.AllHeaders {
				headers = burp.FilterHeaders(headers)
			}
			respSummary = ResponseSummary{
				StatusCode: parsedResp.StatusCode,
				Headers:    burp.FlattenHeaders(headers),
				Body:       parsedResp.Body,
				BodySize:   parsedResp.BodySize,
				Truncated:  parsedResp.Truncated,
			}
		}

		return nil, GetRequestOutput{
			Request:  reqSummary,
			Response: respSummary,
		}, nil
	}
}

// RegisterGetRequestTool registers the burp_get_request tool.
func RegisterGetRequestTool(server *mcp.Server, client *burp.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "burp_get_request",
		Description: `Get full request+response from proxy history by index. ` +
			`Returns {request: {method, path, host, headers, body}, response: {statusCode, headers, body, bodySize}}.`,
	}, getRequestHandler(client))
}
