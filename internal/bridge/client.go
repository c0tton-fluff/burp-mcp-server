package bridge

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "http://127.0.0.1:9877"
	DefaultTimeout = 30 * time.Second
)

// Client talks to the burp-bridge Kotlin extension HTTP API on :9877.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a bridge client from env or defaults.
func NewClient() *Client {
	base := os.Getenv("BURP_BRIDGE_URL")
	if base == "" {
		base = DefaultBaseURL
	}

	timeout := DefaultTimeout
	if raw := os.Getenv("BURP_BRIDGE_TIMEOUT"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			timeout = d
		}
	}

	return &Client{
		BaseURL: strings.TrimRight(base, "/"),
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// HealthResponse from GET /api/health.
type HealthResponse struct {
	Status           string `json:"status"`
	BurpVersion      string `json:"burp_version"`
	ExtensionsLoaded int    `json:"extensions_loaded"`
	BridgeVersion    string `json:"bridge_version"`
	Port             int    `json:"port"`
}

// Extension from GET /api/extensions.
type Extension struct {
	Name         string `json:"name"`
	Loaded       bool   `json:"loaded"`
	HasScanCheck bool   `json:"has_scan_check"`
	Type         string `json:"type"`
}

// ExtensionsResponse from GET /api/extensions.
type ExtensionsResponse struct {
	Extensions []Extension `json:"extensions"`
}

// ScanRequest is the POST body for /api/scan.
type ScanRequest struct {
	Request string `json:"request"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	HTTPS   bool   `json:"https"`
	Config  string `json:"config"`
}

// ScanStatus from POST /api/scan and GET /api/scan/:id.
type ScanStatus struct {
	ScanID                string `json:"scan_id"`
	Status                string `json:"status"`
	Target                string `json:"target,omitempty"`
	Config                string `json:"config,omitempty"`
	StartedAt             string `json:"started_at,omitempty"`
	InsertionPointsTested int    `json:"insertion_points_tested,omitempty"`
	InsertionPointsTotal  int    `json:"insertion_points_total,omitempty"`
	ElapsedSeconds        int    `json:"elapsed_seconds,omitempty"`
	FindingsCount         int    `json:"findings_count,omitempty"`
}

// Finding from GET /api/findings.
type Finding struct {
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	URL        string `json:"url"`
	Method     string `json:"method"`
	Detail     string `json:"detail"`
	Extension  string `json:"extension"`
	Request    string `json:"request,omitempty"`
	Response   string `json:"response,omitempty"`
}

// FindingsResponse from GET /api/findings.
type FindingsResponse struct {
	Count    int       `json:"count"`
	Findings []Finding `json:"findings"`
}

// FindingsFilter for GET /api/findings query params.
type FindingsFilter struct {
	ScanID     string
	Severity   string
	Confidence string
	Extension  string
	URL        string
}

// ErrorResponse from the bridge on 4xx/5xx.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// Health calls GET /api/health.
func (c *Client) Health() (*HealthResponse, error) {
	body, err := c.get("/api/health", nil)
	if err != nil {
		return nil, err
	}
	var resp HealthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse health response: %w", err)
	}
	return &resp, nil
}

// ListExtensions calls GET /api/extensions with optional filters.
func (c *Client) ListExtensions(name string, extType string) (*ExtensionsResponse, error) {
	params := url.Values{}
	if name != "" {
		params.Set("name", name)
	}
	if extType != "" {
		params.Set("type", extType)
	}
	body, err := c.get("/api/extensions", params)
	if err != nil {
		return nil, err
	}
	var resp ExtensionsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse extensions response: %w", err)
	}
	return &resp, nil
}

// StartScan calls POST /api/scan.
func (c *Client) StartScan(req ScanRequest) (*ScanStatus, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal scan request: %w", err)
	}
	body, err := c.post("/api/scan", payload)
	if err != nil {
		return nil, err
	}
	var resp ScanStatus
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse scan response: %w", err)
	}
	return &resp, nil
}

// GetScanStatus calls GET /api/scan/:id.
func (c *Client) GetScanStatus(id string) (*ScanStatus, error) {
	body, err := c.get("/api/scan/"+id, nil)
	if err != nil {
		return nil, err
	}
	var resp ScanStatus
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse scan status: %w", err)
	}
	return &resp, nil
}

// GetFindings calls GET /api/findings with filters.
func (c *Client) GetFindings(filter FindingsFilter) (*FindingsResponse, error) {
	params := url.Values{}
	if filter.ScanID != "" {
		params.Set("scan_id", filter.ScanID)
	}
	if filter.Severity != "" {
		params.Set("severity", filter.Severity)
	}
	if filter.Confidence != "" {
		params.Set("confidence", filter.Confidence)
	}
	if filter.Extension != "" {
		params.Set("extension", filter.Extension)
	}
	if filter.URL != "" {
		params.Set("url", filter.URL)
	}
	body, err := c.get("/api/findings", params)
	if err != nil {
		return nil, err
	}
	var resp FindingsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse findings response: %w", err)
	}
	return &resp, nil
}

// CancelScan calls DELETE /api/scan/:id.
func (c *Client) CancelScan(id string) error {
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL+"/api/scan/"+id, nil)
	if err != nil {
		return fmt.Errorf("build cancel request: %w", err)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return wrapConnectionError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("scan %s not found", id)
	}
	if resp.StatusCode >= 400 {
		return parseErrorResponse(resp)
	}
	return nil
}

// get performs a GET request and returns the response body.
func (c *Client) get(path string, params url.Values) ([]byte, error) {
	u := c.BaseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	resp, err := c.HTTPClient.Get(u)
	if err != nil {
		return nil, wrapConnectionError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, parseErrorBody(body, resp.StatusCode)
	}
	return body, nil
}

// post performs a POST request with JSON body.
func (c *Client) post(path string, payload []byte) ([]byte, error) {
	resp, err := c.HTTPClient.Post(
		c.BaseURL+path,
		"application/json",
		strings.NewReader(string(payload)),
	)
	if err != nil {
		return nil, wrapConnectionError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, parseErrorBody(body, resp.StatusCode)
	}
	return body, nil
}

// wrapConnectionError adds user-facing context to connection failures.
func wrapConnectionError(err error) error {
	return fmt.Errorf("bridge unreachable at %s -- is burp-bridge.jar loaded? (%w)",
		DefaultBaseURL, err)
}

// parseErrorResponse reads and formats a bridge error from a response.
func parseErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("bridge returned %d", resp.StatusCode)
	}
	return parseErrorBody(body, resp.StatusCode)
}

// parseErrorBody formats a bridge error from raw JSON.
func parseErrorBody(body []byte, status int) error {
	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
		return fmt.Errorf("bridge error (%d): %s", status, errResp.Error)
	}
	return fmt.Errorf("bridge returned %d: %s", status, string(body))
}
