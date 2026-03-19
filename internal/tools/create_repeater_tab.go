package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CreateRepeaterTabInput is the input for burp_create_repeater_tab.
type CreateRepeaterTabInput struct {
	Raw     string `json:"raw" jsonschema:"required,Raw HTTP request"`
	Host    string `json:"host" jsonschema:"required,Target hostname"`
	Port    int    `json:"port,omitempty" jsonschema:"Target port (default based on TLS)"`
	TLS     *bool  `json:"tls,omitempty" jsonschema:"Use HTTPS (default true)"`
	TabName string `json:"tabName,omitempty" jsonschema:"Repeater tab name"`
}

// CreateRepeaterTabOutput is the output.
type CreateRepeaterTabOutput struct {
	Message string `json:"message"`
}

func createRepeaterTabHandler(client *burp.Client) func(context.Context, *mcp.CallToolRequest, CreateRepeaterTabInput) (*mcp.CallToolResult, CreateRepeaterTabOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input CreateRepeaterTabInput) (*mcp.CallToolResult, CreateRepeaterTabOutput, error) {
		if err := validateRawRequest(input.Raw); err != nil {
			return nil, CreateRepeaterTabOutput{}, err
		}

		t, err := resolveTarget(input.Host, input.Port, input.TLS, "")
		if err != nil {
			return nil, CreateRepeaterTabOutput{}, err
		}

		rawNorm := normalizeRawRequest(input.Raw)

		args := map[string]any{
			"content":        rawNorm,
			"targetHostname": t.Host,
			"targetPort":     t.Port,
			"usesHttps":      t.UseTLS,
		}
		if input.TabName != "" {
			args["tabName"] = input.TabName
		}

		_, err = client.CallTool(ctx, "create_repeater_tab", args)
		if err != nil {
			return nil, CreateRepeaterTabOutput{}, fmt.Errorf("failed to create repeater tab: %w", err)
		}

		tabDesc := input.TabName
		if tabDesc == "" {
			tabDesc = "new tab"
		}

		return nil, CreateRepeaterTabOutput{
			Message: fmt.Sprintf("Created repeater tab '%s' for %s:%d", tabDesc, t.Host, t.Port),
		}, nil
	}
}

// RegisterCreateRepeaterTabTool registers the burp_create_repeater_tab tool.
func RegisterCreateRepeaterTabTool(server *mcp.Server, client *burp.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_create_repeater_tab",
		Description: `Create a Repeater tab with an HTTP request. Params: raw (request), host, port, tls, tabName.`,
	}, createRepeaterTabHandler(client))
}
