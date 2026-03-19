package tools

import (
	"context"
	"testing"
)

func TestEncodeHandler_URL(t *testing.T) {
	handler := encodeHandler()
	_, out, err := handler(context.Background(), nil, EncodeInput{
		Content: "hello world&foo=bar",
		Type:    "url",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Encoded != "hello+world%26foo%3Dbar" {
		t.Errorf("got %q", out.Encoded)
	}
}

func TestEncodeHandler_Base64(t *testing.T) {
	handler := encodeHandler()
	_, out, err := handler(context.Background(), nil, EncodeInput{
		Content: "hello world",
		Type:    "base64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Encoded != "aGVsbG8gd29ybGQ=" {
		t.Errorf("got %q", out.Encoded)
	}
}

func TestEncodeHandler_EmptyContent(t *testing.T) {
	handler := encodeHandler()
	_, _, err := handler(context.Background(), nil, EncodeInput{
		Content: "",
		Type:    "url",
	})
	if err == nil {
		t.Error("expected error for empty content")
	}
}

func TestEncodeHandler_InvalidType(t *testing.T) {
	handler := encodeHandler()
	_, _, err := handler(context.Background(), nil, EncodeInput{
		Content: "test",
		Type:    "rot13",
	})
	if err == nil {
		t.Error("expected error for invalid type")
	}
}

func TestDecodeHandler_URL(t *testing.T) {
	handler := decodeHandler()
	_, out, err := handler(context.Background(), nil, DecodeInput{
		Content: "hello+world%26foo%3Dbar",
		Type:    "url",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Decoded != "hello world&foo=bar" {
		t.Errorf("got %q", out.Decoded)
	}
}

func TestDecodeHandler_Base64(t *testing.T) {
	handler := decodeHandler()
	_, out, err := handler(context.Background(), nil, DecodeInput{
		Content: "aGVsbG8gd29ybGQ=",
		Type:    "base64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Decoded != "hello world" {
		t.Errorf("got %q", out.Decoded)
	}
}

func TestDecodeHandler_Base64URLSafe(t *testing.T) {
	handler := decodeHandler()
	// URL-safe base64 of "test+data/more"
	_, out, err := handler(context.Background(), nil, DecodeInput{
		Content: "dGVzdCtkYXRhL21vcmU=",
		Type:    "base64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Decoded != "test+data/more" {
		t.Errorf("got %q", out.Decoded)
	}
}

func TestDecodeHandler_EmptyContent(t *testing.T) {
	handler := decodeHandler()
	_, _, err := handler(context.Background(), nil, DecodeInput{
		Content: "",
		Type:    "base64",
	})
	if err == nil {
		t.Error("expected error for empty content")
	}
}

func TestDecodeHandler_InvalidType(t *testing.T) {
	handler := decodeHandler()
	_, _, err := handler(context.Background(), nil, DecodeInput{
		Content: "test",
		Type:    "hex",
	})
	if err == nil {
		t.Error("expected error for invalid type")
	}
}
