package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetProxyHistoryInput is the input for burp_get_proxy_history.
type GetProxyHistoryInput struct {
	// Number of entries to return
	Count int `json:"count,omitempty" jsonschema:"Number of entries to return (default 10)"`
	// Offset for pagination
	Offset int `json:"offset,omitempty" jsonschema:"Offset for pagination (default 0)"`
}

// ProxyHistorySummary is a lean proxy history entry.
type ProxyHistorySummary struct {
	ID         int    `json:"id"`
	Method     string `json:"method,omitempty"`
	URL        string `json:"url,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
}

// GetProxyHistoryOutput is the output of burp_get_proxy_history.
type GetProxyHistoryOutput struct {
	Entries []ProxyHistorySummary `json:"entries"`
	Count   int                   `json:"count"`
}

func getProxyHistoryHandler(session *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, GetProxyHistoryInput) (*mcp.CallToolResult, GetProxyHistoryOutput, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input GetProxyHistoryInput) (*mcp.CallToolResult, GetProxyHistoryOutput, error) {
		count := input.Count
		if count <= 0 {
			count = 10
		}
		if count > 50 {
			count = 50
		}

		// Fetch entries one at a time to avoid large SSE payloads that crash
		// the connection. Burp serializes full request+response bodies per
		// entry, so count=N returns N * (req+resp) bytes over SSE.
		// count=1 is small enough; count=5+ crashes the SSE transport.
		var entries []ProxyHistorySummary
		for i := 0; i < count; i++ {
			offset := input.Offset + i

			args := map[string]any{
				"count":  1,
				"offset": offset,
			}

			raw, err := burp.CallTool(ctx, session, "get_proxy_http_history", args)
			if err != nil {
				// If first call fails, propagate error.
				// If we already have entries, stop pagination gracefully.
				if len(entries) == 0 {
					return nil, GetProxyHistoryOutput{}, fmt.Errorf("failed to get proxy history: %w", err)
				}
				break
			}

			raw = trimEndMarker(raw)
			if raw == "" {
				break // no more entries
			}

			entry := parseSingleHistoryEntry(raw, offset+1)
			if entry != nil {
				entries = append(entries, *entry)
			}
		}

		if entries == nil {
			entries = []ProxyHistorySummary{}
		}

		return nil, GetProxyHistoryOutput{
			Entries: entries,
			Count:   len(entries),
		}, nil
	}
}

// parseSingleHistoryEntry parses a single proxy history entry from Burp's
// response (JSON or wrapper format) into a lean summary.
func parseSingleHistoryEntry(raw string, id int) *ProxyHistorySummary {
	// Try JSON parse first (PortSwigger MCP extension format)
	jsonEntries := burp.ParseProxyHistory(raw)
	if len(jsonEntries) > 0 {
		e := jsonEntries[0]
		return &ProxyHistorySummary{
			ID:         id,
			Method:     e.Method,
			URL:        e.URL,
			StatusCode: e.StatusCode,
		}
	}

	// Fallback: extract request/response directly
	reqRaw, respRaw := burp.ExtractRequestResponse(raw)
	if reqRaw == "" {
		return nil
	}

	parsed := burp.ParseRawRequest(reqRaw)
	summary := &ProxyHistorySummary{
		ID:     id,
		Method: parsed.Method,
	}

	if parsed.Host != "" {
		summary.URL = "https://" + parsed.Host + parsed.Path
	} else {
		summary.URL = parsed.Path
	}

	if respRaw != "" {
		resp := burp.ParseHTTPResponse(respRaw, 0, 0)
		if resp != nil {
			summary.StatusCode = resp.StatusCode
		}
	}

	return summary
}

// trimEndMarker strips the Burp pagination sentinel from raw responses.
func trimEndMarker(raw string) string {
	const marker = "Reached end of items"
	if raw == marker {
		return ""
	}
	// Could be appended after a JSON entry
	if idx := len(raw) - len(marker); idx > 0 && raw[idx:] == marker {
		raw = raw[:idx]
	}
	return raw
}

// RegisterGetProxyHistoryTool registers the burp_get_proxy_history tool.
func RegisterGetProxyHistoryTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_get_proxy_history",
		Description: `Get proxy HTTP history summaries. Returns {id, method, url, statusCode} per entry.`,
	}, getProxyHistoryHandler(session))
}
