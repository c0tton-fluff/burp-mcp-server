package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EncodeInput is the input for burp_encode.
type EncodeInput struct {
	// Content to encode
	Content string `json:"content" jsonschema:"required,Content to encode"`
	// Encoding type: url or base64
	Type string `json:"type" jsonschema:"required,Encoding type: url or base64"`
}

// EncodeOutput is the output of burp_encode.
type EncodeOutput struct {
	Encoded string `json:"encoded"`
}

func encodeHandler(session *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, EncodeInput) (*mcp.CallToolResult, EncodeOutput, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input EncodeInput) (*mcp.CallToolResult, EncodeOutput, error) {
		if input.Content == "" {
			return nil, EncodeOutput{}, fmt.Errorf("content is required")
		}

		var toolName string
		switch input.Type {
		case "url":
			toolName = "url_encode"
		case "base64":
			toolName = "base64_encode"
		default:
			return nil, EncodeOutput{}, fmt.Errorf("type must be 'url' or 'base64'")
		}

		result, err := burp.CallTool(ctx, session, toolName, map[string]any{
			"content": input.Content,
		})
		if err != nil {
			return nil, EncodeOutput{}, fmt.Errorf("encode failed: %w", err)
		}

		return nil, EncodeOutput{Encoded: result}, nil
	}
}

// DecodeInput is the input for burp_decode.
type DecodeInput struct {
	// Content to decode
	Content string `json:"content" jsonschema:"required,Content to decode"`
	// Decoding type: url or base64
	Type string `json:"type" jsonschema:"required,Decoding type: url or base64"`
}

// DecodeOutput is the output of burp_decode.
type DecodeOutput struct {
	Decoded string `json:"decoded"`
}

func decodeHandler(session *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, DecodeInput) (*mcp.CallToolResult, DecodeOutput, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, input DecodeInput) (*mcp.CallToolResult, DecodeOutput, error) {
		if input.Content == "" {
			return nil, DecodeOutput{}, fmt.Errorf("content is required")
		}

		var toolName string
		switch input.Type {
		case "url":
			toolName = "url_decode"
		case "base64":
			toolName = "base64_decode"
		default:
			return nil, DecodeOutput{}, fmt.Errorf("type must be 'url' or 'base64'")
		}

		result, err := burp.CallTool(ctx, session, toolName, map[string]any{
			"content": input.Content,
		})
		if err != nil {
			return nil, DecodeOutput{}, fmt.Errorf("decode failed: %w", err)
		}

		return nil, DecodeOutput{Decoded: result}, nil
	}
}

// RegisterEncodeTool registers the burp_encode tool.
func RegisterEncodeTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_encode",
		Description: `Encode content. Params: content, type (url|base64). Returns {encoded}.`,
	}, encodeHandler(session))
}

// RegisterDecodeTool registers the burp_decode tool.
func RegisterDecodeTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_decode",
		Description: `Decode content. Params: content, type (url|base64). Returns {decoded}.`,
	}, decodeHandler(session))
}
