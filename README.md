<p align="center">
  <img src="https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Python-3.6+-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License">
  <a href="https://github.com/c0tton-fluff/burp-mcp-server/releases"><img src="https://img.shields.io/github/v/release/c0tton-fluff/burp-mcp-server" alt="Release"></a>
</p>

# burp-mcp-server

MCP server and standalone CLI for [Burp Suite Professional](https://portswigger.net/burp). Gives AI assistants like Claude Code full access to Burp - send requests, read proxy history, pull scanner findings, stage requests in Repeater/Intruder, and run race condition attacks. All with structured JSON output, body limits, and smart header filtering.

## Why This Exists

Burp's built-in MCP extension returns verbose `HttpRequestResponse{...}` blobs with no body limits, separate HTTP/1.1 and HTTP/2 tools, and 14+ tools that burn context tokens. This project replaces all of that:

| Problem | Solution |
|---------|----------|
| 873KB response blobs | 10KB body limit (configurable per request) |
| 14+ overlapping tools | 10 clean, deduplicated tools |
| Separate HTTP/1.1 and HTTP/2 tools | Unified send with auto protocol detection and caching |
| All headers dumped | Smart filtering - security-relevant headers only by default |
| No batch or race support | Parallel batch send (10 req) and single-packet race attacks (50 req) |
| Java toString output | Structured JSON: `{statusCode, headers, body, bodySize, truncated}` |

## Two Ways to Use

```
MCP Server (for AI assistants)
  Claude Code  -->  stdio  -->  burp-mcp-server (Go)  -->  SSE  -->  Burp Extension (port 9876)

Standalone CLI (for terminal)
  Terminal  -->  burp-cli (Python)  -->  Burp Proxy Listener (port 8080)  -->  Proxy History
```

---

## MCP Server

### Install

**One-liner:**

```bash
curl -fsSL https://raw.githubusercontent.com/c0tton-fluff/burp-mcp-server/main/install.sh | bash
```

**Or** download from [Releases](https://github.com/c0tton-fluff/burp-mcp-server/releases).

<details>
<summary>Build from source</summary>

```bash
git clone https://github.com/c0tton-fluff/burp-mcp-server.git
cd burp-mcp-server
go build -o burp-mcp-server .
```

</details>

### Quick Start

**1. Enable MCP in Burp Suite**

Burp Suite > **MCP** tab > toggle **Enabled** (default `127.0.0.1:9876`).

Uncheck "Require approval for history access" for pentesting/CTF use.

**2. Add to your MCP config**

`~/.mcp.json`:

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

**3. Talk to Claude Code**

```
"Send a GET request to https://example.com"
"Check proxy history for requests to /api"
"Show scanner findings"
"Create a Repeater tab for this login request"
"Batch send these 5 IDOR requests"
"Race the transfer endpoint with 20 requests"
```

### Tools

#### HTTP

| Tool | Description |
|------|-------------|
| `burp_send_request` | Send HTTP request with auto protocol detection, smart headers, body limit |
| `burp_batch_send` | Send up to 10 requests in parallel (IDOR/BAC testing) |
| `burp_race_request` | Single-packet race condition attack with deduplicated output |

#### Proxy and Scanner

| Tool | Description |
|------|-------------|
| `burp_get_proxy_history` | List proxy history with optional regex filter |
| `burp_get_request` | Fetch full request + response from proxy history by index |
| `burp_get_scanner_issues` | Get structured scanner findings |

#### Staging

| Tool | Description |
|------|-------------|
| `burp_create_repeater_tab` | Create named Repeater tab with request |
| `burp_send_to_intruder` | Send request to Intruder |

#### Encoding (local, no Burp roundtrip)

| Tool | Description |
|------|-------------|
| `burp_encode` | URL or Base64 encode |
| `burp_decode` | URL or Base64 decode |

### Response Format

**Default (security headers only):**

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

**Headers-only mode** (`headersOnly: true`) -- useful for recon and fingerprinting:

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

### Race Condition Attack

`burp_race_request` implements the [single-packet attack](https://portswigger.net/research/smashing-the-state-machine) technique from James Kettle's research. It bypasses Burp's proxy entirely for timing precision.

**How it works:**

1. Opens N parallel TLS/TCP connections to the target
2. Sends all-but-last-byte of the HTTP request on each connection
3. Sends the final byte on all connections simultaneously (last-byte sync)
4. Reads and parses all responses in parallel

Same technique as Turbo Intruder -- but callable directly from Claude Code.

**Features:**

- Auto-calculates `Content-Length` from actual body
- Forces HTTP/1.1 via TLS ALPN (avoids HTTP/2 upgrade)
- Deduplicates identical responses by default (saves tokens)
- Returns structured results with per-response body limits

**Deduplicated output (default):**

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

### Batch Requests

`burp_batch_send` sends up to 10 requests in parallel. Tag each request to identify it in results:

```json
{
  "requests": [
    {"raw": "GET /api/users/1 HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer user_token", "tag": "own-profile"},
    {"raw": "GET /api/users/2 HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer user_token", "tag": "other-profile"},
    {"raw": "GET /api/users/1 HTTP/1.1\r\nHost: target.com", "tag": "no-auth"}
  ]
}
```

```json
{
  "responses": [
    {"tag": "own-profile", "statusCode": 200, "body": "{\"id\":1,...}"},
    {"tag": "other-profile", "statusCode": 200, "body": "{\"id\":2,...}"},
    {"tag": "no-auth", "statusCode": 401, "body": "{\"error\":\"unauthorized\"}"}
  ],
  "summary": "3 requests, responses: 2x 200, 1x 401"
}
```

<details>
<summary><strong>Full parameter reference</strong></summary>

#### burp_send_request

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `raw` | string | required | Raw HTTP request including headers and body |
| `host` | string | from Host header | Target host (overrides Host header) |
| `port` | int | 443/80 | Target port |
| `tls` | bool | true | Use HTTPS |
| `bodyLimit` | int | 10000 | Response body byte limit |
| `bodyOffset` | int | 0 | Response body byte offset |
| `allHeaders` | bool | false | Return all headers (default: security-relevant only) |
| `headersOnly` | bool | false | Return only status + headers, skip body |

#### burp_batch_send

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `requests` | array | required | Array of `{raw, host, port, tls, tag}` objects (max 10) |
| `bodyLimit` | int | 10000 | Response body limit per response |
| `allHeaders` | bool | false | Return all headers |

Each request in the array:

| Field | Type | Description |
|-------|------|-------------|
| `raw` | string | Raw HTTP request |
| `host` | string | Target host |
| `port` | int | Target port |
| `tls` | bool | Use HTTPS |
| `tag` | string | Label to identify this request in results |

#### burp_race_request

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `raw` | string | required | Raw HTTP request including headers and body |
| `host` | string | from Host header | Target host |
| `port` | int | 443/80 | Target port |
| `tls` | bool | true | Use HTTPS |
| `count` | int | 10 | Number of concurrent requests (max 50) |
| `bodyLimit` | int | 500 | Response body byte limit per response |
| `showAll` | bool | false | Return all individual responses instead of deduplicated groups |

#### burp_get_proxy_history

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `count` | int | 10 | Number of entries (max 50) |
| `offset` | int | 0 | Pagination offset |
| `regex` | string | | Regex filter for URL/content |

#### burp_get_request

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `index` | int | required | Proxy history index (1-based, from burp_get_proxy_history) |
| `bodyLimit` | int | 10000 | Response body byte limit |
| `bodyOffset` | int | 0 | Response body byte offset |
| `allHeaders` | bool | false | Return all headers |

#### burp_get_scanner_issues

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `count` | int | 10 | Number of issues (max 50) |
| `offset` | int | 0 | Pagination offset |
| `detailLimit` | int | 500 | Max chars per issue detail (-1 = unlimited) |

#### burp_create_repeater_tab / burp_send_to_intruder

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `raw` | string | required | Raw HTTP request |
| `host` | string | required | Target hostname |
| `port` | int | 443/80 | Target port |
| `tls` | bool | true | Use HTTPS |
| `tabName` | string | | Tab name |

#### burp_encode / burp_decode

| Parameter | Type | Description |
|-----------|------|-------------|
| `content` | string | Content to encode/decode |
| `type` | string | `url` or `base64` |

</details>

---

## Standalone CLI

Command-line client for Burp Suite. No MCP required -- sends requests through Burp's proxy listener so they appear in Proxy > HTTP History. Zero dependencies beyond Python stdlib.

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/c0tton-fluff/burp-mcp-server/main/install.sh | TOOL=cli bash
```

**Or** download from [Releases](https://github.com/c0tton-fluff/burp-mcp-server/releases).

### Usage

Requires Burp Suite running with proxy listener on `127.0.0.1:8080` (default).

```bash
# Structured requests (proxied through Burp)
burp send GET https://target.com/api/users
burp send POST https://target.com/api/login -j '{"user":"admin","pass":"test"}'
burp send PUT https://target.com/api/profile -H "Authorization: Bearer tok" -j '{"role":"admin"}'

# Raw HTTP requests
burp raw -f request.txt target.com
echo -e 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' | burp raw

# Race condition attack (last-byte sync, direct -- bypasses proxy)
burp race target.com -f transfer.txt -n 20

# Direct mode (skip proxy)
burp send GET https://target.com/api/health --direct

# Encode / decode
burp encode base64 "hello world"
burp decode url "%3Cscript%3E"
burp encode hex "test"
```

### Commands

| Command | Description |
|---------|-------------|
| `send METHOD URL` | Send structured HTTP request through Burp proxy |
| `raw [HOST]` | Send raw HTTP request from file or stdin |
| `race [HOST]` | Single-packet last-byte sync race condition attack (direct) |
| `encode TYPE VALUE` | Encode value (`url`, `base64`, `hex`) |
| `decode TYPE VALUE` | Decode value (`url`, `base64`, `hex`) |

### Flags

| Flag | Description |
|------|-------------|
| `--proxy` | Burp proxy address (default `127.0.0.1:8080`, or `BURP_PROXY` env var) |
| `--direct` | Skip proxy, connect directly to target |
| `--all-headers` | Return all response headers (default: security-relevant only) |
| `-b, --body-limit` | Response body byte limit (default 10000) |
| `-t, --timeout` | Request timeout in seconds (default 30) |

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Tools not appearing in Claude Code | Verify binary path in `~/.mcp.json`, restart Claude Code |
| Connection refused on port 9876 | Ensure Burp is running with MCP enabled |
| Connection refused on port 8080 | Ensure Burp proxy listener is active |
| Request hangs on first send | HTTP/2 timeout + fallback handles this (15s first time, cached after) |
| Empty proxy history | Only shows browser-proxied traffic, not MCP `send_request` calls |
| Orphaned server process | Built-in parent PID watchdog auto-terminates when Claude Code exits |

MCP logs: `~/.cache/claude-cli-nodejs/*/mcp-logs-burp/`

## Prerequisites

- [Burp Suite Professional](https://portswigger.net/burp) (Community edition has limited MCP support)
- Burp MCP Server extension from BApp Store
- Burp running with MCP enabled before starting Claude Code

## License

MIT
