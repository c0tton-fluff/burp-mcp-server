//go:build integration

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
)

const (
	testTarget  = "lab-1773925725411-8a7vas.labs-app.bugforge.io"
	testBurpURL = "http://127.0.0.1:9876/"
)

func setupClient(t *testing.T) (*burp.Client, context.CancelFunc) {
	t.Helper()
	client, err := burp.NewClient(testBurpURL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	_, err = client.Connect(ctx)
	if err != nil {
		cancel()
		t.Skipf("Burp MCP not available: %v", err)
	}
	return client, cancel
}

func TestIntegration_SendRequest_GET(t *testing.T) {
	client, cancel := setupClient(t)
	defer cancel()
	defer client.Close()
	ctx := context.Background()

	raw := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n\r\n", testTarget)
	parsed := burp.ParseRawRequest(raw)
	target, err := resolveTarget("", 0, nil, parsed.Host)
	if err != nil {
		t.Fatal(err)
	}

	rawNorm := normalizeRawRequest(raw)
	responseText, err := sendWithFallback(ctx, client, rawNorm, parsed, target)
	if err != nil {
		t.Fatalf("sendWithFallback: %v", err)
	}

	resp := burp.ParseHTTPResponse(responseText, 0, 10000)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}

	t.Logf("Status: %d %s", resp.StatusCode, resp.StatusLine)
	t.Logf("Body size: %d bytes", resp.BodySize)
	t.Logf("Headers: %d total", len(resp.Headers))

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(resp.Body, "CopyPasta") {
		t.Error("body should contain 'CopyPasta'")
	}

	filtered := burp.FilterHeaders(resp.Headers)
	t.Logf("Security headers: %v", flatKeys(filtered))
}

func TestIntegration_SendRequest_API(t *testing.T) {
	client, cancel := setupClient(t)
	defer cancel()
	defer client.Close()
	ctx := context.Background()

	raw := fmt.Sprintf("GET /api/snippets HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\n\r\n", testTarget)
	parsed := burp.ParseRawRequest(raw)
	target, err := resolveTarget("", 0, nil, parsed.Host)
	if err != nil {
		t.Fatal(err)
	}

	rawNorm := normalizeRawRequest(raw)
	responseText, err := sendWithFallback(ctx, client, rawNorm, parsed, target)
	if err != nil {
		t.Fatalf("sendWithFallback: %v", err)
	}

	resp := burp.ParseHTTPResponse(responseText, 0, 10000)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}

	t.Logf("API Status: %d", resp.StatusCode)
	t.Logf("API Body: %.200s", resp.Body)

	// Body should be JSON
	if strings.TrimSpace(resp.Body) != "" {
		var js json.RawMessage
		if err := json.Unmarshal([]byte(resp.Body), &js); err == nil {
			t.Logf("API response is valid JSON")
		}
	}
}

func TestIntegration_SendRequest_HeadersOnly(t *testing.T) {
	client, cancel := setupClient(t)
	defer cancel()
	defer client.Close()
	ctx := context.Background()

	raw := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", testTarget)
	parsed := burp.ParseRawRequest(raw)
	target, err := resolveTarget("", 0, nil, parsed.Host)
	if err != nil {
		t.Fatal(err)
	}

	rawNorm := normalizeRawRequest(raw)
	responseText, err := sendWithFallback(ctx, client, rawNorm, parsed, target)
	if err != nil {
		t.Fatalf("sendWithFallback: %v", err)
	}

	resp := burp.ParseHTTPResponse(responseText, 0, 1)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}

	t.Logf("HeadersOnly - Status: %d, BodySize: %d, Body len: %d", resp.StatusCode, resp.BodySize, len(resp.Body))

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if len(resp.Body) > 1 {
		t.Errorf("headersOnly body should be <= 1 byte, got %d", len(resp.Body))
	}
	if resp.BodySize == 0 {
		t.Error("BodySize should be > 0 even in headersOnly mode")
	}
}

func TestIntegration_ProtocolCache(t *testing.T) {
	client, cancel := setupClient(t)
	defer cancel()
	defer client.Close()
	ctx := context.Background()

	raw := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", testTarget)
	parsed := burp.ParseRawRequest(raw)
	target, err := resolveTarget("", 0, nil, parsed.Host)
	if err != nil {
		t.Fatal(err)
	}

	rawNorm := normalizeRawRequest(raw)
	_, err = sendWithFallback(ctx, client, rawNorm, parsed, target)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}

	cached := isHTTP1Only(testTarget)
	t.Logf("Protocol cache for %s: http1Only=%v", testTarget, cached)

	start := time.Now()
	_, err = sendWithFallback(ctx, client, rawNorm, parsed, target)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	t.Logf("Second request: %v (cached=%v)", elapsed, cached)
}

func TestIntegration_RaceRequest(t *testing.T) {
	ctx := context.Background()

	count := 5
	bodyLimit := 500

	rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n\r\n", testTarget)
	rawNorm := normalizeRawRequest(rawReq)
	rawNorm = fixContentLength(rawNorm)

	results, err := executeRace(ctx, testTarget, 443, true, []byte(rawNorm), count, bodyLimit)
	if err != nil {
		t.Fatalf("executeRace: %v", err)
	}

	if len(results) != count {
		t.Fatalf("got %d results, want %d", len(results), count)
	}

	statusCounts := make(map[int]int)
	for i, r := range results {
		statusCounts[r.StatusCode]++
		t.Logf("  [%d] status=%d body=%d bytes", i, r.StatusCode, len(r.Body))
	}
	t.Logf("Race results: %v", statusCounts)

	if statusCounts[200] == 0 {
		t.Error("expected at least some 200 responses")
	}

	groups := dedupeRaceResults(results)
	t.Logf("Deduped into %d groups", len(groups))
	for _, g := range groups {
		t.Logf("  group: %dx %d (body: %.60s...)", g.Count, g.StatusCode, g.Body)
	}
}

func TestIntegration_ParseRealResponse(t *testing.T) {
	client, cancel := setupClient(t)
	defer cancel()
	defer client.Close()
	ctx := context.Background()

	raw := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", testTarget)
	parsed := burp.ParseRawRequest(raw)
	target, err := resolveTarget("", 0, nil, parsed.Host)
	if err != nil {
		t.Fatal(err)
	}

	rawNorm := normalizeRawRequest(raw)
	responseText, err := sendWithFallback(ctx, client, rawNorm, parsed, target)
	if err != nil {
		t.Fatalf("sendWithFallback: %v", err)
	}

	resp := burp.ParseHTTPResponse(responseText, 0, 0)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}

	t.Logf("Full parse:")
	t.Logf("  StatusCode: %d", resp.StatusCode)
	t.Logf("  StatusLine: %s", resp.StatusLine)
	t.Logf("  BodySize: %d", resp.BodySize)
	t.Logf("  Headers: %d", len(resp.Headers))

	flat := burp.FlattenHeaders(resp.Headers)
	out, _ := json.MarshalIndent(flat, "  ", "  ")
	t.Logf("  All headers:\n  %s", string(out))

	filtered := burp.FilterHeaders(resp.Headers)
	secOut, _ := json.MarshalIndent(burp.FlattenHeaders(filtered), "  ", "  ")
	t.Logf("  Security headers:\n  %s", string(secOut))

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestIntegration_ValidateAndResolve(t *testing.T) {
	if err := validateRawRequest(""); err == nil {
		t.Error("should reject empty")
	}
	if err := validateRawRequest("GET / HTTP/1.1\r\n\r\n"); err != nil {
		t.Errorf("should accept valid: %v", err)
	}
	if err := validateRawRequest(strings.Repeat("A", maxRawRequestSize+1)); err == nil {
		t.Error("should reject oversized")
	}

	rt, err := resolveTarget("", 0, nil, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	if rt.Host != testTarget || rt.Port != 443 || !rt.UseTLS {
		t.Errorf("got %+v", rt)
	}
}

func flatKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
