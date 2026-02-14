package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetScannerIssuesInput is the input for burp_get_scanner_issues.
type GetScannerIssuesInput struct {
	// Number of issues to return
	Count int `json:"count,omitempty" jsonschema:"Number of issues to return (default 10)"`
	// Offset for pagination
	Offset int `json:"offset,omitempty" jsonschema:"Offset for pagination (default 0)"`
	// Max characters per issue detail field (default 500, -1 = unlimited)
	DetailLimit int `json:"detailLimit,omitempty" jsonschema:"Max characters per issue detail (default 500, -1 = unlimited)"`
}

// GetScannerIssuesOutput is the output of burp_get_scanner_issues.
type GetScannerIssuesOutput struct {
	Issues []burp.ScannerIssue `json:"issues"`
	Count  int                 `json:"count"`
}

func getScannerIssuesHandler(session *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, GetScannerIssuesInput) (*mcp.CallToolResult, GetScannerIssuesOutput, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input GetScannerIssuesInput) (*mcp.CallToolResult, GetScannerIssuesOutput, error) {
		count := input.Count
		if count <= 0 {
			count = 10
		}
		if count > 50 {
			count = 50
		}

		args := map[string]any{
			"count":  count,
			"offset": input.Offset,
		}

		raw, err := burp.CallTool(ctx, session, "get_scanner_issues", args)
		if err != nil {
			return nil, GetScannerIssuesOutput{}, fmt.Errorf("failed to get scanner issues: %w", err)
		}

		// DetailLimit: default 500, -1 = unlimited (0 treated as default since it's the zero value)
		detailLimit := input.DetailLimit
		if detailLimit == 0 {
			detailLimit = 500
		}
		if detailLimit < 0 {
			detailLimit = 0
		}

		issues := burp.ParseScannerIssues(raw, detailLimit)
		output := GetScannerIssuesOutput{
			Issues: issues,
			Count:  len(issues),
		}
		if output.Issues == nil {
			output.Issues = []burp.ScannerIssue{}
		}

		return nil, output, nil
	}
}

// RegisterGetScannerIssuesTool registers the burp_get_scanner_issues tool.
func RegisterGetScannerIssuesTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_get_scanner_issues",
		Description: `Get scanner findings. Returns structured issues: {name, severity, confidence, url, issueDetail}.`,
	}, getScannerIssuesHandler(session))
}
