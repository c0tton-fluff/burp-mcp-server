package tools

import "testing"

func TestTrimEndMarker_ExactMatch(t *testing.T) {
	got := trimEndMarker("Reached end of items")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestTrimEndMarker_WithWhitespace(t *testing.T) {
	got := trimEndMarker("  Reached end of items  ")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestTrimEndMarker_NewlineSeparated(t *testing.T) {
	raw := `{"request":"GET / HTTP/1.1","response":"HTTP/1.1 200 OK"}

Reached end of items`
	got := trimEndMarker(raw)
	want := `{"request":"GET / HTTP/1.1","response":"HTTP/1.1 200 OK"}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTrimEndMarker_SingleNewline(t *testing.T) {
	raw := "some data\nReached end of items"
	got := trimEndMarker(raw)
	if got != "some data" {
		t.Errorf("got %q, want %q", got, "some data")
	}
}

func TestTrimEndMarker_SuffixNoNewline(t *testing.T) {
	raw := "dataReached end of items"
	got := trimEndMarker(raw)
	want := "data"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTrimEndMarker_NoMarker(t *testing.T) {
	raw := `{"request":"GET / HTTP/1.1"}`
	got := trimEndMarker(raw)
	if got != raw {
		t.Errorf("should return unchanged, got %q", got)
	}
}

func TestTrimEndMarker_Empty(t *testing.T) {
	got := trimEndMarker("")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
