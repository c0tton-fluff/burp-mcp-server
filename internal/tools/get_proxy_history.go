package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetProxyHistoryInput is the input for burp_get_proxy_history.
type GetProxyHistoryInput struct {
	Count  int `json:"count,omitempty" jsonschema:"Number of entries to return (default 10)"`
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

// fetchConcurrency controls how many proxy history entries are fetched in parallel.
const fetchConcurrency = 5

func getProxyHistoryHandler(client *burp.Client) func(context.Context, *mcp.CallToolRequest, GetProxyHistoryInput) (*mcp.CallToolResult, GetProxyHistoryOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input GetProxyHistoryInput) (*mcp.CallToolResult, GetProxyHistoryOutput, error) {
		count := input.Count
		if count <= 0 {
			count = 10
		}
		if count > 50 {
			count = 50
		}

		// Fetch entries with bounded parallelism.
		// Burp serializes full request+response per entry, so count=1 per call
		// avoids crashing the SSE transport (count=5+ causes SSE payload overflow).
		type result struct {
			idx   int
			entry *ProxyHistorySummary
			err   error
		}
		results := make(chan result, count)
		sem := make(chan struct{}, fetchConcurrency)

		for i := 0; i < count; i++ {
			sem <- struct{}{}
			go func(idx int) {
				defer func() { <-sem }()
				offset := input.Offset + idx

				args := map[string]any{
					"count":  1,
					"offset": offset,
				}

				raw, err := client.CallTool(ctx, "get_proxy_http_history", args)
				if err != nil {
					results <- result{idx: idx, err: err}
					return
				}

				raw = trimEndMarker(raw)
				if raw == "" {
					results <- result{idx: idx}
					return
				}

				entry := parseSingleHistoryEntry(raw, offset+1)
				results <- result{idx: idx, entry: entry}
			}(i)
		}

		// Collect results in order
		ordered := make([]*ProxyHistorySummary, count)
		var firstErr error
		for i := 0; i < count; i++ {
			r := <-results
			if r.err != nil && firstErr == nil {
				firstErr = r.err
			}
			ordered[r.idx] = r.entry
		}

		// Build entries slice preserving order, stopping at first gap
		var entries []ProxyHistorySummary
		for _, e := range ordered {
			if e == nil {
				break
			}
			entries = append(entries, *e)
		}

		if len(entries) == 0 && firstErr != nil {
			return nil, GetProxyHistoryOutput{}, fmt.Errorf("failed to get proxy history: %w", firstErr)
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
	if strings.TrimSpace(raw) == marker {
		return ""
	}
	if idx := strings.Index(raw, "\n"+marker); idx >= 0 {
		return strings.TrimSpace(raw[:idx])
	}
	if strings.HasSuffix(raw, marker) {
		return strings.TrimSpace(raw[:len(raw)-len(marker)])
	}
	return raw
}

// RegisterGetProxyHistoryTool registers the burp_get_proxy_history tool.
func RegisterGetProxyHistoryTool(server *mcp.Server, client *burp.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_get_proxy_history",
		Description: `Get proxy HTTP history summaries. Returns {id, method, url, statusCode} per entry.`,
	}, getProxyHistoryHandler(client))
}
