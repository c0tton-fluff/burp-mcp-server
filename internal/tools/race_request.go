package tools

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c0tton-fluff/burp-mcp-server/internal/burp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	raceTimeout    = 30 * time.Second
	maxRaceCount   = 50
	defaultRaceCount = 10
	defaultRaceBodyLimit = 500
)

// RaceRequestInput is the input for the burp_race_request tool.
type RaceRequestInput struct {
	// Raw HTTP request (request line + headers + body)
	Raw string `json:"raw" jsonschema:"required,Raw HTTP request including headers and body"`
	// Target host (overrides Host header)
	Host string `json:"host,omitempty" jsonschema:"Target host (overrides Host header)"`
	// Target port
	Port int `json:"port,omitempty" jsonschema:"Target port (default based on TLS)"`
	// Use HTTPS
	TLS *bool `json:"tls,omitempty" jsonschema:"Use HTTPS (default true)"`
	// Number of concurrent requests (default 10, max 50)
	Count int `json:"count,omitempty" jsonschema:"Number of concurrent requests (default 10, max 50)"`
	// Body limit in bytes per response (default 500)
	BodyLimit int `json:"bodyLimit,omitempty" jsonschema:"Response body byte limit per response (default 500)"`
}

// RaceResponseEntry holds a single response from the race attack.
type RaceResponseEntry struct {
	Index      int    `json:"index"`
	StatusCode int    `json:"statusCode"`
	Body       string `json:"body,omitempty"`
}

// RaceRequestOutput is the output from burp_race_request.
type RaceRequestOutput struct {
	Results []RaceResponseEntry `json:"results"`
	Summary string              `json:"summary"`
}

func raceRequestHandler(_ *mcp.ClientSession) func(context.Context, *mcp.CallToolRequest, RaceRequestInput) (*mcp.CallToolResult, RaceRequestOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input RaceRequestInput) (*mcp.CallToolResult, RaceRequestOutput, error) {
		if input.Raw == "" {
			return nil, RaceRequestOutput{}, fmt.Errorf("raw HTTP request is required")
		}

		parsed := burp.ParseRawRequest(input.Raw)

		// Determine host
		host := input.Host
		if host == "" {
			host = parsed.Host
		}
		if host == "" {
			return nil, RaceRequestOutput{}, fmt.Errorf("host is required (provide in input or Host header)")
		}

		// Parse host:port
		if h, p, err := net.SplitHostPort(host); err == nil {
			host = h
			if input.Port == 0 {
				if pn, err := strconv.Atoi(p); err == nil {
					input.Port = pn
				}
			}
		}

		// Determine TLS
		useTLS := true
		if input.TLS != nil {
			useTLS = *input.TLS
		}

		// Determine port
		port := input.Port
		if port == 0 {
			if useTLS {
				port = 443
			} else {
				port = 80
			}
		}

		// Count defaults and bounds
		count := input.Count
		if count <= 0 {
			count = defaultRaceCount
		}
		if count > maxRaceCount {
			count = maxRaceCount
		}

		// Body limit defaults
		bodyLimit := input.BodyLimit
		if bodyLimit == 0 {
			bodyLimit = defaultRaceBodyLimit
		}

		// Normalize the raw request and fix Content-Length
		rawNorm := normalizeRawRequest(input.Raw)
		rawNorm = fixContentLength(rawNorm)
		rawBytes := []byte(rawNorm)

		// Execute the single-packet race attack
		results, err := executeRace(ctx, host, port, useTLS, rawBytes, count, bodyLimit)
		if err != nil {
			return nil, RaceRequestOutput{}, fmt.Errorf("race attack failed: %w", err)
		}

		// Build summary
		statusCounts := make(map[int]int)
		for _, r := range results {
			statusCounts[r.StatusCode]++
		}
		var parts []string
		for code, cnt := range statusCounts {
			parts = append(parts, fmt.Sprintf("%dx %d", cnt, code))
		}
		summary := fmt.Sprintf("%d requests sent, responses: %s", count, strings.Join(parts, ", "))

		output := RaceRequestOutput{
			Results: results,
			Summary: summary,
		}

		return nil, output, nil
	}
}

// raceConn holds a single connection for the race attack.
type raceConn struct {
	conn   net.Conn
	writer *bufio.Writer
	reader *bufio.Reader
}

// executeRace performs a last-byte synchronization race attack.
// Opens N parallel TCP/TLS connections, sends all-but-last-byte on each,
// then sends the final byte on all connections simultaneously.
func executeRace(ctx context.Context, host string, port int, useTLS bool, rawRequest []byte, count int, bodyLimit int) ([]RaceResponseEntry, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	deadline := time.Now().Add(raceTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	// Phase 1: Open all connections in parallel
	conns := make([]*raceConn, count)
	var connWg sync.WaitGroup
	connErrors := make([]error, count)

	for i := 0; i < count; i++ {
		connWg.Add(1)
		go func(idx int) {
			defer connWg.Done()
			conn, err := dialConn(ctx, addr, host, useTLS, deadline)
			if err != nil {
				connErrors[idx] = err
				return
			}
			conns[idx] = &raceConn{
				conn:   conn,
				writer: bufio.NewWriter(conn),
				reader: bufio.NewReaderSize(conn, 32*1024),
			}
		}(i)
	}
	connWg.Wait()

	// Cleanup on exit
	defer func() {
		for _, rc := range conns {
			if rc != nil {
				rc.conn.Close()
			}
		}
	}()

	// Count successful connections
	ready := 0
	for _, rc := range conns {
		if rc != nil {
			ready++
		}
	}
	if ready == 0 {
		return nil, fmt.Errorf("all %d connections failed: %v", count, connErrors[0])
	}

	// Phase 2: Send all-but-last-byte on each connection
	prefix := rawRequest[:len(rawRequest)-1]
	lastByte := rawRequest[len(rawRequest)-1:]

	for i, rc := range conns {
		if rc == nil {
			continue
		}
		if _, err := rc.writer.Write(prefix); err != nil {
			connErrors[i] = fmt.Errorf("prefix write: %w", err)
			rc.conn.Close()
			conns[i] = nil
			continue
		}
		if err := rc.writer.Flush(); err != nil {
			connErrors[i] = fmt.Errorf("prefix flush: %w", err)
			rc.conn.Close()
			conns[i] = nil
		}
	}

	// Phase 3: Last-byte sync - send final byte on all connections simultaneously
	var gate sync.WaitGroup
	gate.Add(1)
	var sendWg sync.WaitGroup

	for i, rc := range conns {
		if rc == nil {
			continue
		}
		sendWg.Add(1)
		go func(idx int, c *raceConn) {
			defer sendWg.Done()
			gate.Wait() // Block until gate opens
			c.conn.Write(lastByte)
		}(i, rc)
	}

	// Open the gate - all goroutines send the last byte at once
	gate.Done()
	sendWg.Wait()

	// Phase 4: Read all responses in parallel
	results := make([]RaceResponseEntry, count)
	var readWg sync.WaitGroup

	for i, rc := range conns {
		if rc == nil {
			results[i] = RaceResponseEntry{
				Index:      i,
				StatusCode: 0,
				Body:       fmt.Sprintf("connection failed: %v", connErrors[i]),
			}
			continue
		}
		readWg.Add(1)
		go func(idx int, c *raceConn) {
			defer readWg.Done()
			resp, err := readHTTPResponse(c.reader)
			if err != nil {
				results[idx] = RaceResponseEntry{
					Index: idx,
					Body:  fmt.Sprintf("read error: %s", err),
				}
				return
			}
			parsed := burp.ParseHTTPResponse(resp, 0, bodyLimit)
			entry := RaceResponseEntry{Index: idx}
			if parsed != nil {
				entry.StatusCode = parsed.StatusCode
				entry.Body = parsed.Body
			}
			results[idx] = entry
		}(i, rc)
	}
	readWg.Wait()

	return results, nil
}

// dialConn opens a TCP (optionally TLS) connection.
func dialConn(ctx context.Context, addr, host string, useTLS bool, deadline time.Time) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:  10 * time.Second,
		Deadline: deadline,
	}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tcpConn.SetDeadline(deadline)

	if !useTLS {
		return tcpConn, nil
	}

	tlsConn := tls.Client(tcpConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// readHTTPResponse reads a single HTTP response from the buffered reader.
// Handles both Content-Length and chunked transfer encoding.
func readHTTPResponse(reader *bufio.Reader) (string, error) {
	var response strings.Builder

	// Read status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading status line: %w", err)
	}
	response.WriteString(statusLine)

	// Read headers
	contentLength := -1
	chunked := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading headers: %w", err)
		}
		response.WriteString(line)

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break // End of headers
		}

		// Parse Content-Length
		if strings.HasPrefix(strings.ToLower(trimmed), "content-length:") {
			valStr := strings.TrimSpace(trimmed[len("content-length:"):])
			if cl, err := strconv.Atoi(valStr); err == nil {
				contentLength = cl
			}
		}

		// Parse Transfer-Encoding
		if strings.HasPrefix(strings.ToLower(trimmed), "transfer-encoding:") {
			val := strings.TrimSpace(trimmed[len("transfer-encoding:"):])
			if strings.Contains(strings.ToLower(val), "chunked") {
				chunked = true
			}
		}
	}

	// Read body
	if chunked {
		body, err := readChunkedBody(reader)
		if err != nil {
			return response.String(), nil // Return what we have
		}
		response.WriteString(body)
	} else if contentLength > 0 {
		body := make([]byte, contentLength)
		n, err := readFull(reader, body)
		if err != nil && n == 0 {
			return response.String(), nil
		}
		response.Write(body[:n])
	}
	// If contentLength == 0 or -1 with no chunked, no body to read

	return response.String(), nil
}

// readChunkedBody reads a chunked transfer-encoded body.
func readChunkedBody(reader *bufio.Reader) (string, error) {
	var body strings.Builder
	for {
		sizeLine, err := reader.ReadString('\n')
		if err != nil {
			return body.String(), err
		}

		sizeStr := strings.TrimSpace(sizeLine)
		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return body.String(), nil
		}

		if size == 0 {
			// Read trailing \r\n
			reader.ReadString('\n')
			break
		}

		chunk := make([]byte, size)
		n, err := readFull(reader, chunk)
		body.Write(chunk[:n])
		if err != nil {
			return body.String(), err
		}

		// Read trailing \r\n after chunk
		reader.ReadString('\n')
	}
	return body.String(), nil
}

// readFull reads exactly len(buf) bytes from reader.
func readFull(reader *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := reader.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// fixContentLength recalculates the Content-Length header to match the actual body size.
// This prevents 400 errors from servers that reject mismatched Content-Length.
func fixContentLength(raw string) string {
	// Split at the header/body boundary
	sep := "\r\n\r\n"
	idx := strings.Index(raw, sep)
	if idx < 0 {
		return raw
	}

	headerSection := raw[:idx]
	body := raw[idx+len(sep):]

	// Rebuild headers with correct Content-Length
	lines := strings.Split(headerSection, "\r\n")
	var rebuilt []string
	hasCL := false
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			rebuilt = append(rebuilt, fmt.Sprintf("Content-Length: %d", len(body)))
			hasCL = true
		} else {
			rebuilt = append(rebuilt, line)
		}
	}

	// Add Content-Length if body exists but header was missing
	if !hasCL && len(body) > 0 {
		rebuilt = append(rebuilt, fmt.Sprintf("Content-Length: %d", len(body)))
	}

	return strings.Join(rebuilt, "\r\n") + sep + body
}

// RegisterRaceRequestTool registers the burp_race_request tool.
func RegisterRaceRequestTool(server *mcp.Server, session *mcp.ClientSession) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "burp_race_request",
		Description: `Single-packet race condition attack. Sends N identical HTTP requests in one TCP segment for TOCTOU exploitation. ` +
			`Bypasses Burp proxy for timing precision. Returns {results: [{index, statusCode, body}], summary}. ` +
			`Default: 10 requests, 500B body limit per response.`,
	}, raceRequestHandler(session))
}

// MarshalJSON for RaceRequestOutput to produce clean tool output.
func (o RaceRequestOutput) MarshalJSON() ([]byte, error) {
	type Alias RaceRequestOutput
	return json.Marshal(Alias(o))
}
