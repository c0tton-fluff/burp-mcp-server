package tools

import (
	"bufio"
	"strings"
	"testing"
)

func TestFixContentLength_ExistingHeader(t *testing.T) {
	raw := "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 999\r\n\r\n{\"a\":1}"
	fixed := fixContentLength(raw)
	if !strings.Contains(fixed, "Content-Length: 7") {
		t.Errorf("expected Content-Length: 7, got %q", fixed)
	}
	if strings.Contains(fixed, "Content-Length: 999") {
		t.Error("old Content-Length should be replaced")
	}
}

func TestFixContentLength_MissingHeader(t *testing.T) {
	raw := "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{\"a\":1}"
	fixed := fixContentLength(raw)
	if !strings.Contains(fixed, "Content-Length: 7") {
		t.Errorf("expected Content-Length: 7 to be added, got %q", fixed)
	}
}

func TestFixContentLength_NoBody(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	fixed := fixContentLength(raw)
	if strings.Contains(fixed, "Content-Length") {
		t.Error("should not add Content-Length for empty body")
	}
}

func TestFixContentLength_NoDoubleNewline(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: example.com"
	fixed := fixContentLength(raw)
	if fixed != raw {
		t.Errorf("should return unchanged, got %q", fixed)
	}
}

func TestDedupeRaceResults_Groups(t *testing.T) {
	results := []RaceResponseEntry{
		{Index: 0, StatusCode: 200, Body: "ok"},
		{Index: 1, StatusCode: 200, Body: "ok"},
		{Index: 2, StatusCode: 403, Body: "denied"},
		{Index: 3, StatusCode: 200, Body: "ok"},
	}
	groups := dedupeRaceResults(results)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	if groups[0].StatusCode != 200 || groups[0].Count != 3 {
		t.Errorf("group[0] = %+v, want 3x 200", groups[0])
	}
	if groups[1].StatusCode != 403 || groups[1].Count != 1 {
		t.Errorf("group[1] = %+v, want 1x 403", groups[1])
	}
}

func TestDedupeRaceResults_Empty(t *testing.T) {
	groups := dedupeRaceResults(nil)
	if len(groups) != 0 {
		t.Errorf("got %d groups, want 0", len(groups))
	}
}

func TestDedupeRaceResults_AllUnique(t *testing.T) {
	results := []RaceResponseEntry{
		{Index: 0, StatusCode: 200, Body: "a"},
		{Index: 1, StatusCode: 200, Body: "b"},
		{Index: 2, StatusCode: 200, Body: "c"},
	}
	groups := dedupeRaceResults(results)
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}
}

func TestReadHTTPResponse_ContentLength(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	reader := bufio.NewReader(strings.NewReader(raw))
	resp, err := readHTTPResponse(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "hello") {
		t.Errorf("body missing from response: %q", resp)
	}
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("status missing from response: %q", resp)
	}
}

func TestReadHTTPResponse_Chunked(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	reader := bufio.NewReader(strings.NewReader(raw))
	resp, err := readHTTPResponse(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "hello") {
		t.Errorf("chunked body missing: %q", resp)
	}
}

func TestReadHTTPResponse_NoBody(t *testing.T) {
	raw := "HTTP/1.1 204 No Content\r\nServer: test\r\n\r\n"
	reader := bufio.NewReader(strings.NewReader(raw))
	resp, err := readHTTPResponse(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "204") {
		t.Errorf("status missing: %q", resp)
	}
}
