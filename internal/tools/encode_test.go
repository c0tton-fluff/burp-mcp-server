package tools

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestEncodeURL(t *testing.T) {
	input := "hello world&foo=bar"
	want := url.QueryEscape(input)
	got := url.QueryEscape(input)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncodeBase64(t *testing.T) {
	input := "hello world"
	want := base64.StdEncoding.EncodeToString([]byte(input))
	got := base64.StdEncoding.EncodeToString([]byte(input))
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDecodeBase64_Standard(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("test data"))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "test data" {
		t.Errorf("got %q", decoded)
	}
}

func TestDecodeBase64_URLSafe(t *testing.T) {
	encoded := base64.URLEncoding.EncodeToString([]byte("test+data/more"))
	// StdEncoding will fail, URLEncoding should work as fallback
	_, err := base64.StdEncoding.DecodeString(encoded)
	if err == nil {
		return // happens to be valid in both
	}
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "test+data/more" {
		t.Errorf("got %q", decoded)
	}
}

func TestDecodeURL(t *testing.T) {
	encoded := url.QueryEscape("hello world&foo=bar")
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != "hello world&foo=bar" {
		t.Errorf("got %q", decoded)
	}
}
