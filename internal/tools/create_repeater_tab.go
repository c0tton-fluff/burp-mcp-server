package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CreateRepeaterTabInput is the input for burp_create_repeater_tab.
type CreateRepeaterTabInput struct {
	// Raw HTTP request
	Raw string `json:"raw" jsonschema:"required,Raw HTTP request"`
	// Target host
	Host string `json:"host" jsonschema:"required,Target hostname"`
	// Target port
	Port int `json:"port,omitempty" jsonschema:"Target port (default based on TLS)"`
	// Use HTTPS
	TLS *bool `json:"tls,omitempty" jsonschema:"Use HTTPS (default true)"`
	// Tab name
	TabName string `json:"tabName,omitempty" jsonschema:"Repeater tab name"`
}

// CreateRepeaterTabOutput is the output.
type CreateRepeaterTabOutput struct {
	Message string `json:"message"`
}

func createRepeaterTabHandler(session *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, CreateRepeaterTabInput) (*mcp.CallToolResult, CreateRepeaterTabOutput, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input CreateRepeaterTabInput) (*mcp.CallToolResult, CreateRepeaterTabOutput, error) {
		if input.Raw == "" {
			return nil, CreateRepeaterTabOutput{}, fmt.Errorf("raw HTTP request is required")
		}

		useTLS := true
		if input.TLS != nil {
			useTLS = *input.TLS
		}

		port := input.Port
		if port == 0 {
			if useTLS {
				port = 443
			} else {
				port = 80
			}
		}

		// Normalize line endings
		rawNorm := normalizeRawRequest(input.Raw)

		args := map[string]any{
			"content":        rawNorm,
			"targetHostname": input.Host,
			"targetPort":     port,
			"usesHttps":      useTLS,
		}
		if input.TabName != "" {
			args["tabName"] = input.TabName
		}

		_, err := burp.CallTool(ctx, session, "create_repeater_tab", args)
		if err != nil {
			return nil, CreateRepeaterTabOutput{}, fmt.Errorf("failed to create repeater tab: %w", err)
		}

		tabDesc := input.TabName
		if tabDesc == "" {
			tabDesc = "new tab"
		}

		return nil, CreateRepeaterTabOutput{
			Message: fmt.Sprintf("Created repeater tab '%s' for %s:%d", tabDesc, input.Host, port),
		}, nil
	}
}

// RegisterCreateRepeaterTabTool registers the burp_create_repeater_tab tool.
func RegisterCreateRepeaterTabTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_create_repeater_tab",
		Description: `Create a Repeater tab with an HTTP request. Params: raw (request), host, port, tls, tabName.`,
	}, createRepeaterTabHandler(session))
}
