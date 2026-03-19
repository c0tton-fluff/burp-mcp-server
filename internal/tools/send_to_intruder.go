package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SendToIntruderInput is the input for burp_send_to_intruder.
type SendToIntruderInput struct {
	Raw     string `json:"raw" jsonschema:"required,Raw HTTP request"`
	Host    string `json:"host" jsonschema:"required,Target hostname"`
	Port    int    `json:"port,omitempty" jsonschema:"Target port (default based on TLS)"`
	TLS     *bool  `json:"tls,omitempty" jsonschema:"Use HTTPS (default true)"`
	TabName string `json:"tabName,omitempty" jsonschema:"Intruder tab name"`
}

// SendToIntruderOutput is the output.
type SendToIntruderOutput struct {
	Message string `json:"message"`
}

func sendToIntruderHandler(client *burp.Client) func(context.Context, *mcp.CallToolRequest, SendToIntruderInput) (*mcp.CallToolResult, SendToIntruderOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input SendToIntruderInput) (*mcp.CallToolResult, SendToIntruderOutput, error) {
		if err := validateRawRequest(input.Raw); err != nil {
			return nil, SendToIntruderOutput{}, err
		}

		t, err := resolveTarget(input.Host, input.Port, input.TLS, "")
		if err != nil {
			return nil, SendToIntruderOutput{}, err
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

		_, err = client.CallTool(ctx, "send_to_intruder", args)
		if err != nil {
			return nil, SendToIntruderOutput{}, fmt.Errorf("failed to send to intruder: %w", err)
		}

		tabDesc := input.TabName
		if tabDesc == "" {
			tabDesc = "new tab"
		}

		return nil, SendToIntruderOutput{
			Message: fmt.Sprintf("Sent to Intruder tab '%s' for %s:%d", tabDesc, t.Host, t.Port),
		}, nil
	}
}

// RegisterSendToIntruderTool registers the burp_send_to_intruder tool.
func RegisterSendToIntruderTool(server *mcp.Server, client *burp.Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_send_to_intruder",
		Description: `Send HTTP request to Intruder. Params: raw (request), host, port, tls, tabName.`,
	}, sendToIntruderHandler(client))
}
