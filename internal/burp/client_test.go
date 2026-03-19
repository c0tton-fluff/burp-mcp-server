package burp

import (
	"fmt"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestIsConnectionError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"connection closed", fmt.Errorf("connection closed"), true},
		{"client is closing", fmt.Errorf("client is closing"), true},
		{"EOF", fmt.Errorf("EOF"), true},
		{"wrapped EOF", fmt.Errorf("read: %w", fmt.Errorf("EOF")), true},
		{"timeout", fmt.Errorf("context deadline exceeded"), false},
		{"random error", fmt.Errorf("something else"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isConnectionError(tt.err); got != tt.want {
				t.Errorf("isConnectionError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestExtractText_Single(t *testing.T) {
	result := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "hello"},
		},
	}
	got := ExtractText(result)
	if got != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestExtractText_Multiple(t *testing.T) {
	result := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "line1"},
			&mcp.TextContent{Text: "line2"},
		},
	}
	got := ExtractText(result)
	if got != "line1\nline2" {
		t.Errorf("got %q, want line1\\nline2", got)
	}
}

func TestExtractText_Empty(t *testing.T) {
	result := &mcp.CallToolResult{}
	got := ExtractText(result)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestClient_SessionAndGen(t *testing.T) {
	c := &Client{generation: 5}
	_, gen := c.sessionAndGen()
	if gen != 5 {
		t.Errorf("generation = %d, want 5", gen)
	}
}

func TestClient_ReconnectIfNeeded_SkipsWhenAlreadyReconnected(t *testing.T) {
	// If generation has advanced (another goroutine reconnected),
	// reconnectIfNeeded should return the current session without reconnecting.
	c := &Client{generation: 10}
	// Call with stale generation (9) -- should NOT try to reconnect
	session, err := c.reconnectIfNeeded(9)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Session is nil since we never connected, but the point is it didn't
	// attempt a network reconnect (which would fail and return error)
	_ = session
	// Generation should not have changed
	if c.generation != 10 {
		t.Errorf("generation = %d, want 10 (should not increment)", c.generation)
	}
}
