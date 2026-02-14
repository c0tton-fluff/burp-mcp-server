package burp

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// UnwrapResponse extracts the HTTP response from Burp's
// HttpRequestResponse{httpRequest=..., httpResponse=..., messageAnnotations=...} format.
// If the text is already a raw HTTP response, returns it unchanged.
func UnwrapResponse(raw string) string {
	// Step 1: Strip messageAnnotations suffix
	// Format: ", messageAnnotations=Annotations{comment='...', highlightColor=...}}"
	const annMarker = ", messageAnnotations=Annotations{"
	if idx := strings.LastIndex(raw, annMarker); idx >= 0 {
		raw = raw[:idx]
	}

	// Step 2: Extract httpResponse= section
	const respMarker = ", httpResponse="
	if idx := strings.Index(raw, respMarker); idx >= 0 {
		return raw[idx+len(respMarker):]
	}

	// Not wrapped — return as-is (might be a raw HTTP response already)
	return raw
}

// UnwrapRequest extracts the HTTP request from Burp's HttpRequestResponse wrapper.
func UnwrapRequest(raw string) string {
	const annMarker = ", messageAnnotations=Annotations{"
	if idx := strings.LastIndex(raw, annMarker); idx >= 0 {
		raw = raw[:idx]
	}

	const respMarker = ", httpResponse="
	requestPart := raw
	if idx := strings.Index(raw, respMarker); idx >= 0 {
		requestPart = raw[:idx]
	}

	// Strip HttpRequestResponse{httpRequest= prefix
	const reqPrefix = "HttpRequestResponse{httpRequest="
	if strings.HasPrefix(requestPart, reqPrefix) {
		return requestPart[len(reqPrefix):]
	}

	// Also try just httpRequest= prefix
	const reqPrefix2 = "httpRequest="
	if strings.HasPrefix(requestPart, reqPrefix2) {
		return requestPart[len(reqPrefix2):]
	}

	return requestPart
}

// ParsedHTTPResponse holds a parsed HTTP response.
type ParsedHTTPResponse struct {
	StatusCode int               `json:"statusCode"`
	StatusLine string            `json:"statusLine"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	BodySize   int               `json:"bodySize"`
	Truncated  bool              `json:"truncated,omitempty"`
}

// ParseHTTPResponse parses a raw HTTP response string into structured parts.
// Applies bodyOffset and bodyLimit to the body content.
func ParseHTTPResponse(raw string, bodyOffset, bodyLimit int) *ParsedHTTPResponse {
	if raw == "" {
		return nil
	}

	result := &ParsedHTTPResponse{
		Headers: make(map[string]string),
	}

	// Split headers and body at the blank line
	var headerSection string
	var bodyBytes []byte

	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
		headerSection = raw[:idx]
		bodyBytes = []byte(raw[idx+4:])
	} else if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		headerSection = raw[:idx]
		bodyBytes = []byte(raw[idx+2:])
	} else {
		// No body, just headers
		headerSection = raw
	}

	// Parse status line and headers
	reader := bufio.NewReader(strings.NewReader(headerSection))

	// Status line
	statusLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return result
	}
	statusLine = strings.TrimSpace(statusLine)
	result.StatusLine = statusLine

	// Extract status code from status line (e.g. "HTTP/1.1 200 OK" or "HTTP/2 200")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) >= 2 {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			result.StatusCode = code
		}
	}

	// Parse headers
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" && err != nil {
			break
		}
		if line == "" {
			if err != nil {
				break
			}
			continue
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			result.Headers[key] = value
		}
		if err != nil {
			break
		}
	}

	// Body handling
	result.BodySize = len(bodyBytes)

	if len(bodyBytes) > 0 {
		// Apply offset
		if bodyOffset > 0 {
			if bodyOffset >= len(bodyBytes) {
				bodyBytes = []byte{}
			} else {
				bodyBytes = bodyBytes[bodyOffset:]
			}
		}

		// Apply limit
		if bodyLimit > 0 && len(bodyBytes) > bodyLimit {
			bodyBytes = bodyBytes[:bodyLimit]
			result.Truncated = true
		}

		result.Body = string(bodyBytes)
	}

	return result
}

// ParsedHTTPRequest holds a parsed HTTP request.
type ParsedHTTPRequest struct {
	Method  string
	Path    string
	Host    string
	Headers map[string]string
	Body    string
}

// ParseRawRequest parses a raw HTTP request string to extract method, path, host, headers, body.
func ParseRawRequest(raw string) *ParsedHTTPRequest {
	result := &ParsedHTTPRequest{
		Headers: make(map[string]string),
	}

	// Normalize line endings
	raw = strings.ReplaceAll(raw, "\r\n", "\n")

	// Split headers and body
	var headerSection, body string
	if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		headerSection = raw[:idx]
		body = raw[idx+2:]
	} else {
		headerSection = raw
	}

	result.Body = body

	lines := strings.Split(headerSection, "\n")
	if len(lines) == 0 {
		return result
	}

	// Parse request line: "GET /path HTTP/1.1"
	requestLine := strings.TrimSpace(lines[0])
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) >= 2 {
		result.Method = parts[0]
		result.Path = parts[1]
	}

	// Parse headers
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			result.Headers[key] = value
			if strings.EqualFold(key, "host") {
				result.Host = value
			}
		}
	}

	return result
}

// ProxyHistoryEntry holds a parsed proxy history entry.
type ProxyHistoryEntry struct {
	ID            int    `json:"id"`
	Method        string `json:"method,omitempty"`
	URL           string `json:"url,omitempty"`
	StatusCode    int    `json:"statusCode,omitempty"`
	ContentLength int    `json:"contentLength,omitempty"`
}

// proxyEntryRegex matches patterns like:
// "1 | GET | https://example.com/path | 200 | 1234"
// or Burp's verbose format.
var proxyEntryRegex = regexp.MustCompile(`(\d+)\s*\|\s*(\w+)\s*\|\s*(https?://\S+)\s*\|\s*(\d+)`)

// ParseProxyHistory parses Burp's proxy history output into structured entries.
// The format varies, so we try multiple parsing strategies.
func ParseProxyHistory(raw string) []ProxyHistoryEntry {
	if raw == "" {
		return nil
	}

	var entries []ProxyHistoryEntry

	// Strategy 1: Try line-by-line table format
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "=") {
			continue
		}

		matches := proxyEntryRegex.FindStringSubmatch(line)
		if len(matches) >= 5 {
			id, _ := strconv.Atoi(matches[1])
			statusCode, _ := strconv.Atoi(matches[4])
			entries = append(entries, ProxyHistoryEntry{
				ID:         id,
				Method:     matches[2],
				URL:        matches[3],
				StatusCode: statusCode,
			})
			continue
		}

		// Strategy 2: Try parsing HttpRequestResponse blocks
		if strings.Contains(line, "HttpRequestResponse{") {
			entry := parseHttpRequestResponseEntry(line)
			if entry != nil {
				entries = append(entries, *entry)
			}
		}
	}

	// Strategy 3: If no entries found, try parsing as a single block
	if len(entries) == 0 && strings.Contains(raw, "HttpRequestResponse{") {
		blocks := splitHttpRequestResponseBlocks(raw)
		for i, block := range blocks {
			entry := parseHttpRequestResponseBlock(block, i+1)
			if entry != nil {
				entries = append(entries, *entry)
			}
		}
	}

	return entries
}

// parseHttpRequestResponseEntry parses a single-line HttpRequestResponse entry.
func parseHttpRequestResponseEntry(line string) *ProxyHistoryEntry {
	entry := &ProxyHistoryEntry{}

	// Extract httpRequest to get method and path
	if idx := strings.Index(line, "httpRequest="); idx >= 0 {
		reqStart := idx + len("httpRequest=")
		// Find the first line of the request
		rest := line[reqStart:]
		if spaceIdx := strings.IndexAny(rest, "\r\n,}"); spaceIdx > 0 {
			requestLine := rest[:spaceIdx]
			parts := strings.Fields(requestLine)
			if len(parts) >= 2 {
				entry.Method = parts[0]
				entry.URL = parts[1]
			}
		}
	}

	return entry
}

// splitHttpRequestResponseBlocks splits raw text into HttpRequestResponse blocks.
func splitHttpRequestResponseBlocks(raw string) []string {
	var blocks []string
	remaining := raw
	for {
		idx := strings.Index(remaining, "HttpRequestResponse{")
		if idx < 0 {
			break
		}
		// Find matching closing brace (simple nesting)
		start := idx
		depth := 0
		end := -1
		for i := start; i < len(remaining); i++ {
			if remaining[i] == '{' {
				depth++
			} else if remaining[i] == '}' {
				depth--
				if depth == 0 {
					end = i + 1
					break
				}
			}
		}
		if end > start {
			blocks = append(blocks, remaining[start:end])
			remaining = remaining[end:]
		} else {
			break
		}
	}
	return blocks
}

// parseHttpRequestResponseBlock parses a multi-line HttpRequestResponse block.
func parseHttpRequestResponseBlock(block string, id int) *ProxyHistoryEntry {
	entry := &ProxyHistoryEntry{ID: id}

	// Extract request method and URL from httpRequest field
	if idx := strings.Index(block, "httpRequest="); idx >= 0 {
		reqStart := idx + len("httpRequest=")
		rest := block[reqStart:]
		// Find the request line
		reader := bufio.NewReader(bytes.NewReader([]byte(rest)))
		requestLine, _ := reader.ReadString('\n')
		requestLine = strings.TrimSpace(requestLine)
		parts := strings.Fields(requestLine)
		if len(parts) >= 2 {
			entry.Method = parts[0]
		}
	}

	// Try to extract Host header for URL construction
	if idx := strings.Index(block, "Host:"); idx >= 0 {
		rest := block[idx+5:]
		if nlIdx := strings.IndexAny(rest, "\r\n"); nlIdx > 0 {
			entry.URL = strings.TrimSpace(rest[:nlIdx])
		}
	}

	// Extract status code from httpResponse
	if idx := strings.Index(block, "httpResponse="); idx >= 0 {
		respStart := idx + len("httpResponse=")
		rest := block[respStart:]
		reader := bufio.NewReader(bytes.NewReader([]byte(rest)))
		statusLine, _ := reader.ReadString('\n')
		statusLine = strings.TrimSpace(statusLine)
		parts := strings.SplitN(statusLine, " ", 3)
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				entry.StatusCode = code
			}
		}
	}

	return entry
}

// ScannerIssue holds a parsed scanner issue.
type ScannerIssue struct {
	Name        string `json:"name"`
	Severity    string `json:"severity,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	URL         string `json:"url,omitempty"`
	IssueDetail string `json:"issueDetail,omitempty"`
}

// ParseScannerIssues parses Burp's scanner output into structured findings.
// detailLimit controls the max length of each issue's detail field (0 = unlimited).
func ParseScannerIssues(raw string, detailLimit int) []ScannerIssue {
	if raw == "" {
		return nil
	}

	var issues []ScannerIssue

	// Split by common delimiters between issues
	// Burp typically separates issues with blank lines or separators
	blocks := splitIssueBlocks(raw)

	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}

		issue := ScannerIssue{}

		// Extract fields using key-value patterns
		lines := strings.Split(block, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			lower := strings.ToLower(line)

			if strings.HasPrefix(lower, "issue:") || strings.HasPrefix(lower, "name:") || strings.HasPrefix(lower, "issue name:") {
				issue.Name = extractValue(line)
			} else if strings.HasPrefix(lower, "severity:") {
				issue.Severity = extractValue(line)
			} else if strings.HasPrefix(lower, "confidence:") {
				issue.Confidence = extractValue(line)
			} else if strings.HasPrefix(lower, "url:") || strings.HasPrefix(lower, "path:") {
				issue.URL = extractValue(line)
			} else if strings.HasPrefix(lower, "detail:") || strings.HasPrefix(lower, "issue detail:") {
				detail := extractValue(line)
				if detailLimit > 0 && len(detail) > detailLimit {
					detail = detail[:detailLimit] + "..."
				}
				issue.IssueDetail = detail
			}
		}

		// If we couldn't parse structured fields, use the whole block as name
		if issue.Name == "" && len(block) > 0 {
			// Might be a single-line format
			if len(block) > 200 {
				issue.Name = block[:200] + "..."
			} else {
				issue.Name = block
			}
		}

		if issue.Name != "" {
			issues = append(issues, issue)
		}
	}

	return issues
}

// splitIssueBlocks splits scanner output into individual issue blocks.
func splitIssueBlocks(raw string) []string {
	// Try splitting by double newlines first
	blocks := strings.Split(raw, "\n\n")
	if len(blocks) > 1 {
		return blocks
	}

	// Try splitting by separator lines
	lines := strings.Split(raw, "\n")
	var blocks2 []string
	var current strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isSeparatorLine(trimmed) {
			if current.Len() > 0 {
				blocks2 = append(blocks2, current.String())
				current.Reset()
			}
			continue
		}
		if current.Len() > 0 {
			current.WriteString("\n")
		}
		current.WriteString(line)
	}
	if current.Len() > 0 {
		blocks2 = append(blocks2, current.String())
	}

	if len(blocks2) > 1 {
		return blocks2
	}

	// Return the whole thing as one block
	return []string{raw}
}

func isSeparatorLine(line string) bool {
	if len(line) < 3 {
		return false
	}
	for _, c := range line {
		if c != '-' && c != '=' && c != '*' {
			return false
		}
	}
	return true
}

func extractValue(line string) string {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return line
	}
	return strings.TrimSpace(line[idx+1:])
}
