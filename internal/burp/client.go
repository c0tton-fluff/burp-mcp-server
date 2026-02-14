package burp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DefaultToolTimeout is the max time for a single Burp tool call.
const DefaultToolTimeout = 30 * time.Second

// Client wraps the MCP client connection to Burp's SSE endpoint.
type Client struct {
	endpoint string
	client   *mcp.Client
	session  *mcp.ClientSession
}

// NewClient creates a new Burp MCP client.
func NewClient(endpoint string) (*Client, error) {
	impl := &mcp.Implementation{
		Name:    "burp-mcp-client",
		Version: "1.0.0",
	}
	client := mcp.NewClient(impl, nil)

	return &Client{
		endpoint: endpoint,
		client:   client,
	}, nil
}

// Connect establishes the SSE connection to Burp's MCP extension.
func (c *Client) Connect(ctx context.Context) (*mcp.ClientSession, error) {
	transport := &mcp.SSEClientTransport{
		Endpoint: c.endpoint,
	}

	session, err := c.client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("SSE connect failed: %w", err)
	}
	c.session = session
	return session, nil
}

// Close terminates the connection.
func (c *Client) Close() {
	if c.session != nil {
		c.session.Close()
	}
}

// CallTool calls a tool on the Burp MCP extension and returns the text content.
// Applies a 30s timeout to prevent hanging on slow/unresponsive targets.
func CallTool(ctx context.Context, session *mcp.ClientSession, name string, args map[string]any) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultToolTimeout)
	defer cancel()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("call %s: timed out after %s", name, DefaultToolTimeout)
		}
		return "", fmt.Errorf("call %s: %w", name, err)
	}
	if result.IsError {
		text := ExtractText(result)
		return "", fmt.Errorf("Burp error: %s", text)
	}
	return ExtractText(result), nil
}

// CallToolWithTimeout calls a tool with a custom timeout.
func CallToolWithTimeout(ctx context.Context, session *mcp.ClientSession, name string, args map[string]any, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("call %s: timed out after %s", name, timeout)
		}
		return "", fmt.Errorf("call %s: %w", name, err)
	}
	if result.IsError {
		text := ExtractText(result)
		return "", fmt.Errorf("Burp error: %s", text)
	}
	return ExtractText(result), nil
}

// ExtractText extracts all text content from a CallToolResult.
func ExtractText(result *mcp.CallToolResult) string {
	var text string
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			if text != "" {
				text += "\n"
			}
			text += tc.Text
		}
	}
	return text
}
