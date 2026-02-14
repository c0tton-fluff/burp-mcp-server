package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SendToIntruderInput is the input for burp_send_to_intruder.
type SendToIntruderInput struct {
	// Raw HTTP request
	Raw string `json:"raw" jsonschema:"required,Raw HTTP request"`
	// Target host
	Host string `json:"host" jsonschema:"required,Target hostname"`
	// Target port
	Port int `json:"port,omitempty" jsonschema:"Target port (default based on TLS)"`
	// Use HTTPS
	TLS *bool `json:"tls,omitempty" jsonschema:"Use HTTPS (default true)"`
	// Tab name
	TabName string `json:"tabName,omitempty" jsonschema:"Intruder tab name"`
}

// SendToIntruderOutput is the output.
type SendToIntruderOutput struct {
	Message string `json:"message"`
}

func sendToIntruderHandler(session *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, SendToIntruderInput) (*mcp.CallToolResult, SendToIntruderOutput, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input SendToIntruderInput) (*mcp.CallToolResult, SendToIntruderOutput, error) {
		if input.Raw == "" {
			return nil, SendToIntruderOutput{}, fmt.Errorf("raw HTTP request is required")
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

		_, err := burp.CallTool(ctx, session, "send_to_intruder", args)
		if err != nil {
			return nil, SendToIntruderOutput{}, fmt.Errorf("failed to send to intruder: %w", err)
		}

		tabDesc := input.TabName
		if tabDesc == "" {
			tabDesc = "new tab"
		}

		return nil, SendToIntruderOutput{
			Message: fmt.Sprintf("Sent to Intruder tab '%s' for %s:%d", tabDesc, input.Host, port),
		}, nil
	}
}

// RegisterSendToIntruderTool registers the burp_send_to_intruder tool.
func RegisterSendToIntruderTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_send_to_intruder",
		Description: `Send HTTP request to Intruder. Params: raw (request), host, port, tls, tabName.`,
	}, sendToIntruderHandler(session))
}
