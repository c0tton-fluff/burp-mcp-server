package tools

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxBatchSize = 10

// BatchRequest is a single request in a batch.
type BatchRequest struct {
	Raw  string `json:"raw" jsonschema:"required,Raw HTTP request"`
	Host string `json:"host,omitempty" jsonschema:"Target host"`
	Port int    `json:"port,omitempty" jsonschema:"Target port"`
	TLS  *bool  `json:"tls,omitempty" jsonschema:"Use HTTPS (default true)"`
	Tag  string `json:"tag,omitempty" jsonschema:"Label to identify this request in results"`
}

// BatchSendInput is the input for burp_batch_send.
type BatchSendInput struct {
	Requests   []BatchRequest `json:"requests" jsonschema:"required,Array of requests to send in parallel"`
	BodyLimit  int            `json:"bodyLimit,omitempty" jsonschema:"Response body limit per response (default 10000)"`
	AllHeaders bool           `json:"allHeaders,omitempty" jsonschema:"Return all headers (default: security-relevant only)"`
}

// BatchResponseEntry is one response in the batch output.
type BatchResponseEntry struct {
	Tag        string         `json:"tag,omitempty"`
	StatusCode int            `json:"statusCode"`
	Headers    map[string]any `json:"headers,omitempty"`
	Body       string         `json:"body,omitempty"`
	BodySize   int            `json:"bodySize"`
	Truncated  bool           `json:"truncated,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// BatchSendOutput is the output of burp_batch_send.
type BatchSendOutput struct {
	Responses []BatchResponseEntry `json:"responses"`
	Summary   string               `json:"summary"`
}

func batchSendHandler(client *burp.Client) func(context.Context, *mcp.CallToolRequest, BatchSendInput) (*mcp.CallToolResult, BatchSendOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input BatchSendInput) (*mcp.CallToolResult, BatchSendOutput, error) {
		if len(input.Requests) == 0 {
			return nil, BatchSendOutput{}, fmt.Errorf("requests array is required")
		}
		if len(input.Requests) > maxBatchSize {
			return nil, BatchSendOutput{}, fmt.Errorf("max %d requests per batch", maxBatchSize)
		}

		bodyLimit := input.BodyLimit
		if bodyLimit == 0 {
			bodyLimit = defaultBodyLimit
		}

		responses := make([]BatchResponseEntry, len(input.Requests))
		var wg sync.WaitGroup

		for i, req := range input.Requests {
			wg.Add(1)
			go func(idx int, r BatchRequest) {
				defer wg.Done()
				responses[idx] = executeSingleRequest(
					ctx, client, r, bodyLimit, input.AllHeaders,
				)
			}(i, req)
		}
		wg.Wait()

		statusCounts := make(map[int]int)
		errCount := 0
		for _, r := range responses {
			if r.Error != "" {
				errCount++
			} else {
				statusCounts[r.StatusCode]++
			}
		}
		var parts []string
		for code, cnt := range statusCounts {
			parts = append(parts, fmt.Sprintf("%dx %d", cnt, code))
		}
		if errCount > 0 {
			parts = append(parts, fmt.Sprintf("%dx error", errCount))
		}
		summary := fmt.Sprintf(
			"%d requests, responses: %s",
			len(input.Requests), strings.Join(parts, ", "),
		)

		return nil, BatchSendOutput{
			Responses: responses,
			Summary:   summary,
		}, nil
	}
}

func executeSingleRequest(
	ctx context.Context,
	client *burp.Client,
	req BatchRequest,
	bodyLimit int,
	allHeaders bool,
) BatchResponseEntry {
	entry := BatchResponseEntry{Tag: req.Tag}

	if err := validateRawRequest(req.Raw); err != nil {
		entry.Error = err.Error()
		return entry
	}

	parsed := burp.ParseRawRequest(req.Raw)

	t, err := resolveTarget(req.Host, req.Port, req.TLS, parsed.Host)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}

	rawNorm := normalizeRawRequest(req.Raw)
	responseText, err := sendWithFallback(ctx, client, rawNorm, parsed, t)
	if err != nil {
		entry.Error = err.Error()
		return entry
	}

	resp := burp.ParseHTTPResponse(responseText, 0, bodyLimit)
	if resp == nil {
		entry.Error = "failed to parse response"
		return entry
	}

	entry.StatusCode = resp.StatusCode
	entry.Body = resp.Body
	entry.BodySize = resp.BodySize
	entry.Truncated = resp.Truncated

	headers := resp.Headers
	if !allHeaders {
		headers = burp.FilterHeaders(headers)
	}
	entry.Headers = burp.FlattenHeaders(headers)

	return entry
}

// RegisterBatchSendTool registers the burp_batch_send tool.
func RegisterBatchSendTool(server *mcp.Server, client *burp.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "burp_batch_send",
		Description: `Send multiple HTTP requests in parallel. Max 10. ` +
			`Input: {requests: [{raw, host, port, tls, tag}], bodyLimit, allHeaders}. ` +
			`Returns {responses: [{tag, statusCode, headers, body}], summary}. For IDOR/BAC testing.`,
	}, batchSendHandler(client))
}
