package tools

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EncodeInput is the input for burp_encode.
type EncodeInput struct {
	Content string `json:"content" jsonschema:"required,Content to encode"`
	Type    string `json:"type" jsonschema:"required,Encoding type: url or base64"`
}

// EncodeOutput is the output of burp_encode.
type EncodeOutput struct {
	Encoded string `json:"encoded"`
}

func encodeHandler(_ *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, EncodeInput) (*mcp.CallToolResult, EncodeOutput, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, input EncodeInput) (*mcp.CallToolResult, EncodeOutput, error) {
		if input.Content == "" {
			return nil, EncodeOutput{}, fmt.Errorf("content is required")
		}

		var encoded string
		switch input.Type {
		case "url":
			encoded = url.QueryEscape(input.Content)
		case "base64":
			encoded = base64.StdEncoding.EncodeToString([]byte(input.Content))
		default:
			return nil, EncodeOutput{}, fmt.Errorf("type must be 'url' or 'base64'")
		}

		return nil, EncodeOutput{Encoded: encoded}, nil
	}
}

// DecodeInput is the input for burp_decode.
type DecodeInput struct {
	Content string `json:"content" jsonschema:"required,Content to decode"`
	Type    string `json:"type" jsonschema:"required,Decoding type: url or base64"`
}

// DecodeOutput is the output of burp_decode.
type DecodeOutput struct {
	Decoded string `json:"decoded"`
}

func decodeHandler(_ *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, DecodeInput) (*mcp.CallToolResult, DecodeOutput, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, input DecodeInput) (*mcp.CallToolResult, DecodeOutput, error) {
		if input.Content == "" {
			return nil, DecodeOutput{}, fmt.Errorf("content is required")
		}

		var decoded string
		var err error
		switch input.Type {
		case "url":
			decoded, err = url.QueryUnescape(input.Content)
			if err != nil {
				return nil, DecodeOutput{}, fmt.Errorf("url decode: %w", err)
			}
		case "base64":
			b, err := base64.StdEncoding.DecodeString(input.Content)
			if err != nil {
				// Try URL-safe base64 as fallback
				b, err = base64.URLEncoding.DecodeString(input.Content)
				if err != nil {
					return nil, DecodeOutput{}, fmt.Errorf("base64 decode: %w", err)
				}
			}
			decoded = string(b)
		default:
			return nil, DecodeOutput{}, fmt.Errorf("type must be 'url' or 'base64'")
		}

		return nil, DecodeOutput{Decoded: decoded}, nil
	}
}

// RegisterEncodeTool registers the burp_encode tool.
func RegisterEncodeTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_encode",
		Description: `Encode content locally. Params: content, type (url|base64). Returns {encoded}.`,
	}, encodeHandler(session))
}

// RegisterDecodeTool registers the burp_decode tool.
func RegisterDecodeTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "burp_decode",
		Description: `Decode content locally. Params: content, type (url|base64). Returns {decoded}.`,
	}, decodeHandler(session))
}
