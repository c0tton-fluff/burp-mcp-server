# burp-mcp-server

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/c0tton-fluff/burp-mcp-server)](https://github.com/c0tton-fluff/burp-mcp-server/releases)

MCP server for [Burp Suite Professional](https://portswigger.net/burp) integration. Enables AI assistants like Claude Code to send requests, read proxy history, access scanner findings, and stage requests in Repeater/Intruder — with clean structured responses, body limits, and auto HTTP/2 detection.

## Why

Burp's native MCP extension returns verbose `HttpRequestResponse{...}` blobs with no body limits, separate HTTP/1.1 and HTTP/2 tools, and 14+ tools that waste context. This binary replaces all of that with 7 clean tools, 2KB body limits, auto HTTP version detection, and structured JSON output.

## Features

- **Unified HTTP send** — Auto-detects HTTP/2 with 15s timeout, falls back to HTTP/1.1
- **Body limits** — 2KB default, configurable per request (no more 873KB response blobs)
- **Clean output** — `{statusCode, headers, body, bodySize, truncated}` instead of Java toString blobs
- **Proxy history** — Lean summaries with optional regex filter
- **Scanner findings** — Structured `{name, severity, confidence, url, issueDetail}`
- **Repeater/Intruder** — Stage requests for manual follow-up

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

### burp_get_proxy_history
| Parameter | Type | Description |
|-----------|------|-------------|
| `count` | int | Number of entries (default 10) |
| `offset` | int | Pagination offset |
| `regex` | string | Regex filter for URL/content |
| `include` | string[] | `requestHeaders`, `requestBody`, `responseHeaders`, `responseBody` |
| `bodyLimit` | int | Body byte limit (default 2000) |
| `bodyOffset` | int | Body byte offset |

### burp_get_scanner_issues
| Parameter | Type | Description |
|-----------|------|-------------|
| `count` | int | Number of issues (default 10) |
| `offset` | int | Pagination offset |

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
  "body": "{\"flag\":\"bug{...}\"}",
  "bodySize": 48,
  "truncated": false
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
