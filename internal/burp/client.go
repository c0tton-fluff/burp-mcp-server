package burp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DefaultToolTimeout is the max time for a single Burp tool call.
const DefaultToolTimeout = 30 * time.Second

// Client wraps the MCP client connection to Burp's SSE endpoint.
// Automatically reconnects when the SSE connection drops.
type Client struct {
	endpoint string
	client   *mcp.Client
	session  *mcp.ClientSession
	mu       sync.Mutex
	ctx      context.Context
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
	c.ctx = ctx
	transport := &mcp.SSEClientTransport{
		Endpoint: c.endpoint,
	}

	session, err := c.client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("SSE connect failed: %w", err)
	}
	c.mu.Lock()
	c.session = session
	c.mu.Unlock()
	return session, nil
}

// reconnect attempts to re-establish the SSE connection after a drop.
func (c *Client) reconnect() (*mcp.ClientSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close old session if it exists
	if c.session != nil {
		c.session.Close()
	}

	// Create fresh client and connect
	impl := &mcp.Implementation{
		Name:    "burp-mcp-client",
		Version: "1.0.0",
	}
	c.client = mcp.NewClient(impl, nil)

	transport := &mcp.SSEClientTransport{
		Endpoint: c.endpoint,
	}

	session, err := c.client.Connect(c.ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("SSE reconnect failed: %w", err)
	}
	c.session = session
	fmt.Fprintf(os.Stderr, "Reconnected to Burp MCP\n")
	return session, nil
}

// Session returns the current session, reconnecting if needed.
func (c *Client) Session() *mcp.ClientSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// Close terminates the connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		c.session.Close()
	}
}

// isConnectionError returns true if the error indicates a dead SSE connection.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection closed") ||
		strings.Contains(msg, "client is closing") ||
		strings.Contains(msg, "EOF")
}

// CallTool calls a tool on the Burp MCP extension and returns the text content.
// Automatically reconnects and retries once on connection errors.
func CallTool(ctx context.Context, session *mcp.ClientSession, name string, args map[string]any) (string, error) {
	text, err := callToolOnce(ctx, session, name, args, DefaultToolTimeout)
	if err != nil && isConnectionError(err) {
		// Try to reconnect via the global client
		if globalClient != nil {
			newSession, reconErr := globalClient.reconnect()
			if reconErr != nil {
				return "", fmt.Errorf("call %s: %w (reconnect also failed: %v)", name, err, reconErr)
			}
			return callToolOnce(ctx, newSession, name, args, DefaultToolTimeout)
		}
	}
	return text, err
}

// CallToolWithTimeout calls a tool with a custom timeout.
// Automatically reconnects and retries once on connection errors.
func CallToolWithTimeout(ctx context.Context, session *mcp.ClientSession, name string, args map[string]any, timeout time.Duration) (string, error) {
	text, err := callToolOnce(ctx, session, name, args, timeout)
	if err != nil && isConnectionError(err) {
		if globalClient != nil {
			newSession, reconErr := globalClient.reconnect()
			if reconErr != nil {
				return "", fmt.Errorf("call %s: %w (reconnect also failed: %v)", name, err, reconErr)
			}
			return callToolOnce(ctx, newSession, name, args, timeout)
		}
	}
	return text, err
}

func callToolOnce(ctx context.Context, session *mcp.ClientSession, name string, args map[string]any, timeout time.Duration) (string, error) {
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

// globalClient holds the singleton client for reconnection from CallTool.
var globalClient *Client

// SetGlobalClient sets the global client instance for auto-reconnection.
func SetGlobalClient(c *Client) {
	globalClient = c
}
