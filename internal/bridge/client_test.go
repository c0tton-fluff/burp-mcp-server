package bridge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &Client{
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	}
}

func TestHealth(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(HealthResponse{
			Status:           "ok",
			BurpVersion:      "2026.3.1",
			ExtensionsLoaded: 5,
			BridgeVersion:    "1.0.0",
			Port:             9877,
		})
	})

	resp, err := client.Health()
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Fatalf("expected ok, got %s", resp.Status)
	}
	if resp.ExtensionsLoaded != 5 {
		t.Fatalf("expected 5 extensions, got %d", resp.ExtensionsLoaded)
	}
}

func TestListExtensions(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/extensions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		// Verify query params pass through
		name := r.URL.Query().Get("name")
		if name != "Proto" {
			t.Fatalf("expected name=Proto, got %q", name)
		}
		json.NewEncoder(w).Encode(ExtensionsResponse{
			Extensions: []Extension{
				{
					Name:         "Server-Side Prototype Pollution Scanner",
					Loaded:       true,
					HasScanCheck: true,
					Type:         "active",
				},
			},
		})
	})

	resp, err := client.ListExtensions("Proto", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(resp.Extensions))
	}
	if !resp.Extensions[0].HasScanCheck {
		t.Fatal("expected has_scan_check=true")
	}
}

func TestStartScan(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/scan" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Config != "heavy" {
			t.Fatalf("expected config=heavy, got %s", req.Config)
		}

		json.NewEncoder(w).Encode(ScanStatus{
			ScanID:    "a1b2c3d4",
			Status:    "running",
			Target:    "POST /api/organization",
			Config:    "heavy",
			StartedAt: "2026-04-07T19:30:00Z",
		})
	})

	status, err := client.StartScan(ScanRequest{
		Request: "POST /api/organization HTTP/1.1\r\nHost: target.com\r\n\r\n{}",
		Host:    "target.com",
		Port:    443,
		HTTPS:   true,
		Config:  "heavy",
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.ScanID != "a1b2c3d4" {
		t.Fatalf("expected scan_id=a1b2c3d4, got %s", status.ScanID)
	}
	if status.Status != "running" {
		t.Fatalf("expected status=running, got %s", status.Status)
	}
}

func TestGetScanStatus(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/scan/a1b2c3d4" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(ScanStatus{
			ScanID:                "a1b2c3d4",
			Status:                "running",
			InsertionPointsTested: 3,
			InsertionPointsTotal:  7,
			ElapsedSeconds:        45,
			FindingsCount:         1,
		})
	})

	s, err := client.GetScanStatus("a1b2c3d4")
	if err != nil {
		t.Fatal(err)
	}
	if s.InsertionPointsTested != 3 {
		t.Fatalf("expected 3 tested, got %d", s.InsertionPointsTested)
	}
}

func TestGetFindings(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/findings" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		sev := r.URL.Query().Get("severity")
		if sev != "high" {
			t.Fatalf("expected severity=high, got %q", sev)
		}
		json.NewEncoder(w).Encode(FindingsResponse{
			Count: 1,
			Findings: []Finding{
				{
					Name:       "Server-side prototype pollution",
					Severity:   "high",
					Confidence: "firm",
					URL:        "https://target.com/api/organization",
					Method:     "POST",
					Extension:  "PP Scanner",
				},
			},
		})
	})

	resp, err := client.GetFindings(FindingsFilter{Severity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Count != 1 {
		t.Fatalf("expected 1 finding, got %d", resp.Count)
	}
}

func TestCancelScan(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/api/scan/a1b2c3d4" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
	})

	if err := client.CancelScan("a1b2c3d4"); err != nil {
		t.Fatal(err)
	}
}

func TestCancelScanNotFound(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	err := client.CancelScan("nonexistent")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestBridgeError(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error: "invalid request format",
			Code:  "INVALID_REQUEST",
		})
	})

	_, err := client.Health()
	if err == nil {
		t.Fatal("expected error")
	}
	expected := "bridge error (400): invalid request format"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestConnectionError(t *testing.T) {
	client := &Client{
		BaseURL:    "http://127.0.0.1:1", // nothing listening
		HTTPClient: http.DefaultClient,
	}

	_, err := client.Health()
	if err == nil {
		t.Fatal("expected connection error")
	}
}
