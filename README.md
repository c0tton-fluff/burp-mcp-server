# burp-mcp-server

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/c0tton-fluff/burp-mcp-server)](https://github.com/c0tton-fluff/burp-mcp-server/releases)

MCP server for [Burp Suite Professional](https://portswigger.net/burp) integration. Enables AI assistants like Claude Code to send requests, read proxy history, access scanner findings, stage requests in Repeater/Intruder, and run race condition attacks -- with clean structured responses, body limits, and smart header filtering.

## Why

Burp's native MCP extension returns verbose `HttpRequestResponse{...}` blobs with no body limits, separate HTTP/1.1 and HTTP/2 tools, and 14+ tools that waste context. This binary replaces all of that with 11 clean tools, 2KB body limits, smart header filtering, protocol caching, batch requests, and structured JSON output.

## Features

- **Smart header filtering** -- Returns only security-relevant headers by default (Set-Cookie, CSP, CORS, etc). Use `allHeaders: true` for everything.
- **Unified HTTP send** -- Auto-detects HTTP/2 with 15s timeout, falls back to HTTP/1.1. Caches protocol per host to skip failed HTTP/2 on repeat requests.
- **Body limits** -- 2KB default, configurable per request (no more 873KB response blobs)
- **Headers-only mode** -- `headersOnly: true` skips the body entirely for fast recon/fingerprinting
- **Batch send** -- Fire up to 10 requests in parallel in a single tool call for IDOR/BAC testing
- **Clean output** -- `{statusCode, headers, body, bodySize, truncated}` instead of Java toString blobs
- **Proxy history** -- Lean summaries with optional regex filter, plus fetch full request/response by index
- **Scanner findings** -- Structured `{name, severity, confidence, url, issueDetail}`
- **Repeater/Intruder** -- Stage requests for manual follow-up
- **Race condition attack** -- Last-byte sync across parallel connections with deduplicated output
- **Local encode/decode** -- URL and Base64 encoding handled locally in Go (no SSE roundtrip)

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
"Batch send these 5 IDOR requests"
"Race the transfer endpoint with 20 requests"
```

## Tools Reference

### HTTP

| Tool | Description |
|------|-------------|
| `burp_send_request` | Send HTTP request with auto protocol detection, smart headers, body limit |
| `burp_batch_send` | Send up to 10 requests in parallel (for IDOR/BAC testing) |
| `burp_race_request` | Single-packet race condition attack with deduplicated output |

### Proxy & Scanner

| Tool | Description |
|------|-------------|
| `burp_get_proxy_history` | List proxy history with optional regex filter |
| `burp_get_request` | Fetch full request + response from proxy history by index |
| `burp_get_scanner_issues` | Get structured scanner findings |

### Staging

| Tool | Description |
|------|-------------|
| `burp_create_repeater_tab` | Create named Repeater tab with request |
| `burp_send_to_intruder` | Send request to Intruder |

### Encoding

| Tool | Description |
|------|-------------|
| `burp_encode` | URL or Base64 encode (local, no Burp roundtrip) |
| `burp_decode` | URL or Base64 decode (local, no Burp roundtrip) |

<details>
<summary>Full parameter reference</summary>

### burp_send_request
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `raw` | string | required | Raw HTTP request including headers and body |
| `host` | string | from Host header | Target host (overrides Host header) |
| `port` | int | 443/80 | Target port |
| `tls` | bool | true | Use HTTPS |
| `bodyLimit` | int | 2000 | Response body byte limit |
| `bodyOffset` | int | 0 | Response body byte offset |
| `allHeaders` | bool | false | Return all headers (default: security-relevant only) |
| `headersOnly` | bool | false | Return only status + headers, skip body |

### burp_batch_send
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `requests` | array | required | Array of `{raw, host, port, tls, tag}` objects (max 10) |
| `bodyLimit` | int | 2000 | Response body limit per response |
| `allHeaders` | bool | false | Return all headers |

Each request in the array:
| Field | Type | Description |
|-------|------|-------------|
| `raw` | string | Raw HTTP request |
| `host` | string | Target host |
| `port` | int | Target port |
| `tls` | bool | Use HTTPS |
| `tag` | string | Label to identify this request in results |

### burp_race_request
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `raw` | string | required | Raw HTTP request including headers and body |
| `host` | string | from Host header | Target host |
| `port` | int | 443/80 | Target port |
| `tls` | bool | true | Use HTTPS |
| `count` | int | 10 | Number of concurrent requests (max 50) |
| `bodyLimit` | int | 500 | Response body byte limit per response |
| `showAll` | bool | false | Return all individual responses instead of deduplicated groups |

### burp_get_proxy_history
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `count` | int | 10 | Number of entries (max 50) |
| `offset` | int | 0 | Pagination offset |
| `regex` | string | | Regex filter for URL/content |

### burp_get_request
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `index` | int | required | Proxy history index (1-based, from burp_get_proxy_history) |
| `bodyLimit` | int | 2000 | Response body byte limit |
| `bodyOffset` | int | 0 | Response body byte offset |
| `allHeaders` | bool | false | Return all headers |

### burp_get_scanner_issues
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `count` | int | 10 | Number of issues (max 50) |
| `offset` | int | 0 | Pagination offset |
| `detailLimit` | int | 500 | Max chars per issue detail (-1 = unlimited) |

### burp_create_repeater_tab / burp_send_to_intruder
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `raw` | string | required | Raw HTTP request |
| `host` | string | required | Target hostname |
| `port` | int | 443/80 | Target port |
| `tls` | bool | true | Use HTTPS |
| `tabName` | string | | Tab name |

### burp_encode / burp_decode
| Parameter | Type | Description |
|-----------|------|-------------|
| `content` | string | Content to encode/decode |
| `type` | string | `url` or `base64` |

</details>

## Response Format

Default response (security headers only):

```json
{
  "statusCode": 200,
  "headers": {
    "Content-Type": "application/json; charset=utf-8",
    "Set-Cookie": "session=abc123; HttpOnly; Secure"
  },
  "body": "{\"id\":1,\"username\":\"admin\",\"role\":\"superuser\"}",
  "bodySize": 52,
  "truncated": false
}
```

Headers-only mode (`headersOnly: true`) omits `body` -- useful for recon:

```json
{
  "statusCode": 200,
  "headers": {
    "Content-Type": "text/html",
    "Server": "nginx/1.24.0",
    "X-Powered-By": "Express"
  },
  "bodySize": 87342
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
- Deduplicates identical responses by default (saves tokens)
- Returns structured results with per-response body limits

**Example usage with Claude Code:**

```
"Race the convert-currency endpoint with 20 concurrent requests"
```

**Default response (deduplicated):**

```json
{
  "groups": [
    {
      "statusCode": 200,
      "body": "{\"message\":\"Currency converted successfully\"}",
      "count": 18,
      "indices": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
    },
    {
      "statusCode": 400,
      "body": "{\"error\":\"Insufficient balance\"}",
      "count": 2,
      "indices": [18, 19]
    }
  ],
  "summary": "20 requests sent, responses: 18x 200, 2x 400"
}
```

Use `showAll: true` to get individual responses instead of groups.

## Batch Requests

`burp_batch_send` sends up to 10 requests in parallel. Tag each request to identify it in results:

```json
{
  "requests": [
    {"raw": "GET /api/users/1 HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer user_token", "tag": "user-view-own"},
    {"raw": "GET /api/users/2 HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer user_token", "tag": "user-view-other"},
    {"raw": "GET /api/users/1 HTTP/1.1\r\nHost: target.com", "tag": "no-auth"}
  ]
}
```

Response:

```json
{
  "responses": [
    {"tag": "user-view-own", "statusCode": 200, "body": "{\"id\":1,...}"},
    {"tag": "user-view-other", "statusCode": 200, "body": "{\"id\":2,...}"},
    {"tag": "no-auth", "statusCode": 401, "body": "{\"error\":\"unauthorized\"}"}
  ],
  "summary": "3 requests, responses: 2x 200, 1x 401"
}
```

## Troubleshooting

| Error | Fix |
|-------|-----|
| Tools not appearing | Verify binary path in `~/.mcp.json`, restart Claude Code |
| Connection refused | Ensure Burp is running with MCP enabled on port 9876 |
| Request hangs | HTTP/2 timeout + fallback handles this automatically (15s first time, cached after) |
| Empty proxy history | Only shows browser-proxied traffic, not MCP `send_request` calls |

Check MCP logs: `~/.cache/claude-cli-nodejs/*/mcp-logs-burp/`

## Prerequisites

- Burp Suite Professional (Community has limited MCP support)
- Burp MCP Server extension from BApp Store
- Burp running with MCP enabled before starting Claude Code

## License

MIT
