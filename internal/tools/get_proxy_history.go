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
	// Regex filter (optional)
	Regex string `json:"regex,omitempty" jsonschema:"Regex filter for URL/content matching"`
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

		// Choose which Burp tool to call based on regex presence
		var toolName string
		args := map[string]any{
			"count":  count,
			"offset": input.Offset,
		}

		if input.Regex != "" {
			toolName = "get_proxy_http_history_regex"
			args["regex"] = input.Regex
		} else {
			toolName = "get_proxy_http_history"
		}

		raw, err := burp.CallTool(ctx, session, toolName, args)
		if err != nil {
			return nil, GetProxyHistoryOutput{}, fmt.Errorf("failed to get proxy history: %w", err)
		}

		entries := burp.ParseProxyHistory(raw)
		output := GetProxyHistoryOutput{
			Count: len(entries),
		}
		for _, e := range entries {
			output.Entries = append(output.Entries, ProxyHistorySummary{
				ID:         e.ID,
				Method:     e.Method,
				URL:        e.URL,
				StatusCode: e.StatusCode,
			})
		}
		if output.Entries == nil {
			output.Entries = []ProxyHistorySummary{}
		}
		return nil, output, nil
	}
}

// RegisterGetProxyHistoryTool registers the burp_get_proxy_history tool.
func RegisterGetProxyHistoryTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_get_proxy_history",
		Description: `Get proxy HTTP history. Optional regex filter. Returns lean summaries: {id, method, url, statusCode}.`,
	}, getProxyHistoryHandler(session))
}
