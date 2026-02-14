package burp

import (
	"strings"
	"testing"
)

// --- UnwrapResponse ---

func TestUnwrapResponse_Wrapped(t *testing.T) {
	input := `HttpRequestResponse{httpRequest=GET / HTTP/1.1, httpResponse=HTTP/1.1 200 OK, messageAnnotations=Annotations{comment='', highlightColor=NONE}}`
	got := UnwrapResponse(input)
	if got != "HTTP/1.1 200 OK" {
		t.Errorf("UnwrapResponse(wrapped) = %q, want %q", got, "HTTP/1.1 200 OK")
	}
}

func TestUnwrapResponse_RawPassthrough(t *testing.T) {
	input := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
	got := UnwrapResponse(input)
	if got != input {
		t.Errorf("UnwrapResponse(raw) should return input unchanged")
	}
}

func TestUnwrapResponse_Empty(t *testing.T) {
	got := UnwrapResponse("")
	if got != "" {
		t.Errorf("UnwrapResponse(\"\") = %q, want \"\"", got)
	}
}

// --- UnwrapRequest ---

func TestUnwrapRequest_FullWrapper(t *testing.T) {
	input := `HttpRequestResponse{httpRequest=GET / HTTP/1.1, httpResponse=HTTP/1.1 200 OK, messageAnnotations=Annotations{comment=''}}`
	got := UnwrapRequest(input)
	if got != "GET / HTTP/1.1" {
		t.Errorf("UnwrapRequest(full) = %q, want %q", got, "GET / HTTP/1.1")
	}
}

func TestUnwrapRequest_RequestOnly(t *testing.T) {
	input := `httpRequest=GET /path HTTP/1.1`
	got := UnwrapRequest(input)
	if got != "GET /path HTTP/1.1" {
		t.Errorf("UnwrapRequest(reqOnly) = %q, want %q", got, "GET /path HTTP/1.1")
	}
}

func TestUnwrapRequest_RawPassthrough(t *testing.T) {
	input := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	got := UnwrapRequest(input)
	if got != input {
		t.Errorf("UnwrapRequest(raw) should return input unchanged")
	}
}

// --- ParseHTTPResponse ---

func TestParseHTTPResponse_Basic(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hello</html>"
	resp := ParseHTTPResponse(raw, 0, 2000)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.Headers["Content-Type"] != "text/html" {
		t.Errorf("Content-Type = %q", resp.Headers["Content-Type"])
	}
	if resp.Body != "<html>hello</html>" {
		t.Errorf("Body = %q", resp.Body)
	}
	if resp.Truncated {
		t.Error("should not be truncated")
	}
}

func TestParseHTTPResponse_HTTP2Status(t *testing.T) {
	raw := "HTTP/2 403\r\nServer: nginx\r\n\r\nForbidden"
	resp := ParseHTTPResponse(raw, 0, 2000)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}
	if resp.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", resp.StatusCode)
	}
}

func TestParseHTTPResponse_BodyLimit(t *testing.T) {
	body := strings.Repeat("A", 100)
	raw := "HTTP/1.1 200 OK\r\n\r\n" + body
	resp := ParseHTTPResponse(raw, 0, 10)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}
	if len(resp.Body) != 10 {
		t.Errorf("Body length = %d, want 10", len(resp.Body))
	}
	if !resp.Truncated {
		t.Error("should be truncated")
	}
	if resp.BodySize != 100 {
		t.Errorf("BodySize = %d, want 100", resp.BodySize)
	}
}

func TestParseHTTPResponse_BodyOffset(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n\r\n0123456789"
	resp := ParseHTTPResponse(raw, 5, 2000)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}
	if resp.Body != "56789" {
		t.Errorf("Body = %q, want \"56789\"", resp.Body)
	}
}

func TestParseHTTPResponse_BodyOffsetBeyondEnd(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n\r\nshort"
	resp := ParseHTTPResponse(raw, 100, 2000)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}
	if resp.Body != "" {
		t.Errorf("Body = %q, want empty", resp.Body)
	}
}

func TestParseHTTPResponse_Empty(t *testing.T) {
	resp := ParseHTTPResponse("", 0, 2000)
	if resp != nil {
		t.Error("ParseHTTPResponse(\"\") should return nil")
	}
}

func TestParseHTTPResponse_UnixLineEndings(t *testing.T) {
	raw := "HTTP/1.1 301 Moved\nLocation: /new\n\nredirect"
	resp := ParseHTTPResponse(raw, 0, 2000)
	if resp == nil {
		t.Fatal("ParseHTTPResponse returned nil")
	}
	if resp.StatusCode != 301 {
		t.Errorf("StatusCode = %d, want 301", resp.StatusCode)
	}
	if resp.Headers["Location"] != "/new" {
		t.Errorf("Location = %q", resp.Headers["Location"])
	}
}

// --- ParseRawRequest ---

func TestParseRawRequest_Standard(t *testing.T) {
	raw := "GET /api/users HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n"
	parsed := ParseRawRequest(raw)
	if parsed.Method != "GET" {
		t.Errorf("Method = %q, want GET", parsed.Method)
	}
	if parsed.Path != "/api/users" {
		t.Errorf("Path = %q, want /api/users", parsed.Path)
	}
	if parsed.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", parsed.Host)
	}
	if parsed.Headers["Accept"] != "application/json" {
		t.Errorf("Accept = %q", parsed.Headers["Accept"])
	}
}

func TestParseRawRequest_WithBody(t *testing.T) {
	raw := "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"user\":\"admin\"}"
	parsed := ParseRawRequest(raw)
	if parsed.Method != "POST" {
		t.Errorf("Method = %q, want POST", parsed.Method)
	}
	if parsed.Body != "{\"user\":\"admin\"}" {
		t.Errorf("Body = %q", parsed.Body)
	}
}

// --- ParseProxyHistory ---

func TestParseProxyHistory_TableFormat(t *testing.T) {
	raw := `1 | GET | https://example.com/path | 200
2 | POST | https://example.com/login | 302
`
	entries := ParseProxyHistory(raw)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].ID != 1 || entries[0].Method != "GET" || entries[0].StatusCode != 200 {
		t.Errorf("entry[0] = %+v", entries[0])
	}
	if entries[1].ID != 2 || entries[1].Method != "POST" || entries[1].StatusCode != 302 {
		t.Errorf("entry[1] = %+v", entries[1])
	}
}

func TestParseProxyHistory_HttpRequestResponseBlock(t *testing.T) {
	// Burp's HttpRequestResponse block parsed via splitHttpRequestResponseBlocks (strategy 3).
	// This format requires the block to NOT appear on a single line-by-line split.
	raw := "HttpRequestResponse{httpRequest=GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n, httpResponse=HTTP/1.1 200 OK\r\n\r\n}"
	entries := ParseProxyHistory(raw)
	if len(entries) == 0 {
		t.Fatal("expected at least 1 entry from HttpRequestResponse block")
	}
}

func TestParseProxyHistory_Empty(t *testing.T) {
	entries := ParseProxyHistory("")
	if entries != nil {
		t.Errorf("ParseProxyHistory(\"\") = %v, want nil", entries)
	}
}

// --- ParseScannerIssues ---

func TestParseScannerIssues_Structured(t *testing.T) {
	raw := `Issue: SQL Injection
Severity: High
Confidence: Certain
URL: https://example.com/search
Detail: The parameter 'q' appears vulnerable to SQL injection.`

	issues := ParseScannerIssues(raw, 500)
	if len(issues) != 1 {
		t.Fatalf("got %d issues, want 1", len(issues))
	}
	if issues[0].Name != "SQL Injection" {
		t.Errorf("Name = %q", issues[0].Name)
	}
	if issues[0].Severity != "High" {
		t.Errorf("Severity = %q", issues[0].Severity)
	}
	if issues[0].URL != "https://example.com/search" {
		t.Errorf("URL = %q", issues[0].URL)
	}
}

func TestParseScannerIssues_DetailLimit(t *testing.T) {
	detail := strings.Repeat("x", 100)
	raw := "Issue: Test\nDetail: " + detail

	issues := ParseScannerIssues(raw, 10)
	if len(issues) != 1 {
		t.Fatalf("got %d issues, want 1", len(issues))
	}
	// 10 chars + "..."
	if len(issues[0].IssueDetail) != 13 {
		t.Errorf("IssueDetail length = %d, want 13", len(issues[0].IssueDetail))
	}
}

func TestParseScannerIssues_DetailUnlimited(t *testing.T) {
	detail := strings.Repeat("x", 1000)
	raw := "Issue: Test\nDetail: " + detail

	issues := ParseScannerIssues(raw, 0)
	if len(issues) != 1 {
		t.Fatalf("got %d issues, want 1", len(issues))
	}
	if len(issues[0].IssueDetail) != 1000 {
		t.Errorf("IssueDetail length = %d, want 1000", len(issues[0].IssueDetail))
	}
}

func TestParseScannerIssues_Empty(t *testing.T) {
	issues := ParseScannerIssues("", 500)
	if issues != nil {
		t.Errorf("ParseScannerIssues(\"\") = %v, want nil", issues)
	}
}

func TestParseScannerIssues_MultipleIssues(t *testing.T) {
	raw := `Issue: XSS
Severity: Medium

Issue: CSRF
Severity: Low`

	issues := ParseScannerIssues(raw, 500)
	if len(issues) != 2 {
		t.Fatalf("got %d issues, want 2", len(issues))
	}
	if issues[0].Name != "XSS" {
		t.Errorf("issues[0].Name = %q", issues[0].Name)
	}
	if issues[1].Name != "CSRF" {
		t.Errorf("issues[1].Name = %q", issues[1].Name)
	}
}
