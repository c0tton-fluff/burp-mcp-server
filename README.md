# burp-mcp-server

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/c0tton-fluff/burp-mcp-server)](https://github.com/c0tton-fluff/burp-mcp-server/releases)

MCP server for [Burp Suite Professional](https://portswigger.net/burp) integration. Enables AI assistants like Claude Code to send requests, read proxy history, access scanner findings, stage requests in Repeater/Intruder, and run race condition attacks -- with clean structured responses, body limits, and auto HTTP/2 detection.

## Why

Burp's native MCP extension returns verbose `HttpRequestResponse{...}` blobs with no body limits, separate HTTP/1.1 and HTTP/2 tools, and 14+ tools that waste context. This binary replaces all of that with 8 clean tools, 2KB body limits, auto HTTP version detection, and structured JSON output.

## Features

- **Unified HTTP send** — Auto-detects HTTP/2 with 15s timeout, falls back to HTTP/1.1
- **Body limits** — 2KB default, configurable per request (no more 873KB response blobs)
- **Clean output** — `{statusCode, headers, body, bodySize, truncated}` instead of Java toString blobs
- **Proxy history** — Lean summaries with optional regex filter
- **Scanner findings** — Structured `{name, severity, confidence, url, issueDetail}`
- **Repeater/Intruder** -- Stage requests for manual follow-up
- **Race condition attack** -- Last-byte sync across parallel connections (like Turbo Intruder, no Burp UI needed)

## Architecture

```
Claude Code  -->  stdio  -->  burp-mcp-server (Go)  -->  SSE  -->  Burp Extension (port 9876)
```

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/c0tton-fluff/burp-mcp-server/main/install.sh | bash
```

Or download from [Releases](https://github.com/c0tton-fluff/burp-mcp-server/releases).

<details>
<summary>Build from source</summary>

```bash
git clone https://github.com/c0tton-fluff/burp-mcp-server.git
cd burp-mcp-server
go build -o burp-mcp-server .
```
</details>

## Quick Start

**1. Enable MCP in Burp**

In Burp Suite: **MCP** tab > toggle **Enabled** (default `127.0.0.1:9876`).

Uncheck "Require approval for history access" for pentesting/CTF use.

**2. Configure MCP client**

Add to `~/.mcp.json`:

```json
{
  "mcpServers": {
    "burp": {
      "command": "burp-mcp-server",
      "args": ["serve"],
      "env": {
        "BURP_MCP_URL": "http://127.0.0.1:9876/sse"
      }
    }
  }
}
```

**3. Use with Claude Code**

```
"Send a GET request to https://example.com"
"Check proxy history for requests to /api"
"Show scanner findings"
"Create a Repeater tab for this login request"
```

## Tools Reference

### HTTP

| Tool | Description |
|------|-------------|
| `burp_send_request` | Send HTTP request with auto HTTP/2 detection and body limit |
| `burp_race_request` | Single-packet race condition attack (last-byte sync, N parallel connections) |
| `burp_get_proxy_history` | List proxy history with optional regex filter |
| `burp_get_scanner_issues` | Get structured scanner findings |

### Staging

| Tool | Description |
|------|-------------|
| `burp_create_repeater_tab` | Create named Repeater tab with request |
| `burp_send_to_intruder` | Send request to Intruder |

### Encoding

| Tool | Description |
|------|-------------|
| `burp_encode` | URL or Base64 encode |
| `burp_decode` | URL or Base64 decode |

<details>
<summary>Full parameter reference</summary>

### burp_send_request
| Parameter | Type | Description |
|-----------|------|-------------|
| `raw` | string | Raw HTTP request including headers and body |
| `host` | string | Target host (overrides Host header) |
| `port` | int | Target port (default based on TLS) |
| `tls` | bool | Use HTTPS (default: true) |
| `bodyLimit` | int | Response body byte limit (default 2000) |
| `bodyOffset` | int | Response body byte offset |

### burp_race_request
| Parameter | Type | Description |
|-----------|------|-------------|
| `raw` | string | Raw HTTP request including headers and body |
| `host` | string | Target host (overrides Host header) |
| `port` | int | Target port (default based on TLS) |
| `tls` | bool | Use HTTPS (default: true) |
| `count` | int | Number of concurrent requests (default 10, max 50) |
| `bodyLimit` | int | Response body byte limit per response (default 500) |

### burp_get_proxy_history
| Parameter | Type | Description |
|-----------|------|-------------|
| `count` | int | Number of entries (default 10) |
| `offset` | int | Pagination offset |
| `regex` | string | Regex filter for URL/content |

### burp_get_scanner_issues
| Parameter | Type | Description |
|-----------|------|-------------|
| `count` | int | Number of issues (default 10) |
| `offset` | int | Pagination offset |
| `detailLimit` | int | Max chars per issue detail (default 500, -1 = unlimited) |

### burp_create_repeater_tab
| Parameter | Type | Description |
|-----------|------|-------------|
| `raw` | string | Raw HTTP request |
| `host` | string | Target hostname |
| `port` | int | Target port |
| `tls` | bool | Use HTTPS (default: true) |
| `tabName` | string | Repeater tab name |

### burp_send_to_intruder
| Parameter | Type | Description |
|-----------|------|-------------|
| `raw` | string | Raw HTTP request |
| `host` | string | Target hostname |
| `port` | int | Target port |
| `tls` | bool | Use HTTPS (default: true) |
| `tabName` | string | Intruder tab name |

### burp_encode / burp_decode
| Parameter | Type | Description |
|-----------|------|-------------|
| `content` | string | Content to encode/decode |
| `type` | string | `url` or `base64` |

</details>

## Response Format

```json
{
  "statusCode": 200,
  "headers": {
    "Content-Type": "application/json; charset=utf-8",
    "X-Powered-By": "Express"
  },
  "body": "{\"id\":1,\"username\":\"admin\",\"role\":\"superuser\"}",
  "bodySize": 52,
  "truncated": false
}
```

## Race Condition Attack

`burp_race_request` implements the [single-packet attack](https://portswigger.net/research/smashing-the-state-machine) technique from James Kettle's research. It bypasses Burp's proxy entirely for timing precision.

**How it works:**

1. Opens N parallel TLS/TCP connections to the target
2. Sends all-but-last-byte of the HTTP request on each connection
3. Sends the final byte on all connections simultaneously (last-byte sync)
4. Reads and parses all responses in parallel

This is the same technique Turbo Intruder uses -- but callable directly from Claude Code with no Burp UI interaction.

**Features:**
- Auto-calculates `Content-Length` from actual body (no manual byte counting)
- Forces HTTP/1.1 via TLS ALPN (avoids HTTP/2 upgrade issues)
- Returns structured results with per-response body limits

**Example usage with Claude Code:**

```
"Race the convert-currency endpoint with 20 concurrent requests"
```

**Example response:**

```json
{
  "results": [
    {"index": 0, "statusCode": 200, "body": "{\"message\":\"Currency converted successfully\",\"flag\":\"bug{...}\"}"},
    {"index": 1, "statusCode": 200, "body": "{\"message\":\"Currency converted successfully\",\"flag\":\"bug{...}\"}"},
    ...
  ],
  "summary": "20 requests sent, responses: 20x 200"
}
```

## Troubleshooting

| Error | Fix |
|-------|-----|
| Tools not appearing | Verify binary path in `~/.mcp.json`, restart Claude Code |
| Connection refused | Ensure Burp is running with MCP enabled on port 9876 |
| Request hangs | HTTP/2 timeout + fallback handles this automatically (15s) |
| Empty proxy history | Only shows browser-proxied traffic, not MCP `send_request` calls |

Check MCP logs: `~/.cache/claude-cli-nodejs/*/mcp-logs-burp/`

## Prerequisites

- Burp Suite Professional (Community has limited MCP support)
- Burp MCP Server extension from BApp Store
- Burp running with MCP enabled before starting Claude Code

## License

MIT
