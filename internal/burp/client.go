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

// maxConcurrentCalls limits parallel SSE calls to Burp's extension.
// Prevents overwhelming the single SSE connection under batch workloads.
const maxConcurrentCalls = 4

// Client wraps the MCP client connection to Burp's SSE endpoint.
// Automatically reconnects when the SSE connection drops.
type Client struct {
	endpoint   string
	client     *mcp.Client
	session    *mcp.ClientSession
	generation uint64 // incremented on each reconnection
	mu         sync.Mutex
	ctx        context.Context
	sem        chan struct{} // concurrency limiter for SSE calls
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
		sem:      make(chan struct{}, maxConcurrentCalls),
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
	c.generation++
	c.mu.Unlock()
	return session, nil
}

// reconnectIfNeeded attempts to re-establish the SSE connection only if no other
// goroutine has already reconnected since the caller observed the failure.
// The generation parameter is the generation the caller saw before the failure.
func (c *Client) reconnectIfNeeded(failedGen uint64) (*mcp.ClientSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Another goroutine already reconnected -- use its session.
	if c.generation != failedGen {
		return c.session, nil
	}

	// Keep reference to old session for deferred cleanup.
	// Don't close it synchronously -- in-flight calls on other goroutines
	// would get "client is closing" errors and fail unnecessarily.
	oldSession := c.session

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
	c.generation++
	fmt.Fprintf(os.Stderr, "Reconnected to Burp MCP\n")

	// Close old session after in-flight calls have time to complete
	if oldSession != nil {
		go func() {
			time.Sleep(5 * time.Second)
			oldSession.Close()
		}()
	}

	return session, nil
}

// Session returns the current session.
func (c *Client) Session() *mcp.ClientSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// sessionAndGen returns the current session and generation atomically.
func (c *Client) sessionAndGen() (*mcp.ClientSession, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session, c.generation
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
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (string, error) {
	return c.CallToolWithTimeout(ctx, name, args, DefaultToolTimeout)
}

// CallToolWithTimeout calls a tool with a custom timeout.
// Automatically reconnects and retries once on connection errors.
func (c *Client) CallToolWithTimeout(ctx context.Context, name string, args map[string]any, timeout time.Duration) (string, error) {
	session, gen := c.sessionAndGen()
	text, err := c.callToolThrottled(ctx, session, name, args, timeout)
	if err != nil && isConnectionError(err) {
		newSession, reconErr := c.reconnectIfNeeded(gen)
		if reconErr != nil {
			return "", fmt.Errorf("call %s: %w (reconnect also failed: %v)", name, err, reconErr)
		}
		return c.callToolThrottled(ctx, newSession, name, args, timeout)
	}
	return text, err
}

// callToolThrottled wraps callToolOnce with concurrency limiting.
func (c *Client) callToolThrottled(ctx context.Context, session *mcp.ClientSession, name string, args map[string]any, timeout time.Duration) (string, error) {
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return callToolOnce(ctx, session, name, args, timeout)
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
	var b strings.Builder
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
