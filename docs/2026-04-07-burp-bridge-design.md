# Burp Bridge -- Extension Orchestrator

**Date:** 2026-04-07
**Status:** Approved
**Repo:** `burp-bridge` (monorepo, extends existing `Burp-Repo/`)

## Problem

Burp Suite extensions (PP Scanner, Param Miner, Backslash Powered Scanner, Retire.js, etc.) are GUI-only. No CLI, no API, no programmatic access. The existing MCP extension exposes 14 core Burp tools but zero extension functionality. Nobody has built this -- we'd be first.

## Solution

Two components in a monorepo:

1. **`burp-bridge.jar`** -- Kotlin Burp extension using Montoya API. Runs inside Burp's JVM, exposes HTTP API on `:9877`. Discovers loaded extensions, triggers targeted audits, aggregates findings.
2. **`burp` CLI (Go)** -- Extends existing Cobra setup with `ext` subcommand group. Talks to bridge extension's HTTP API. Structured JSON output, terse terminal formatting.

## Architecture

```
┌─────────────┐         HTTP/:9877        ┌──────────────────────────┐
│  Go CLI     │ ◄──────────────────────►  │  Kotlin Extension        │
│  `burp ext` │    JSON API               │  `burp-bridge.jar`       │
└─────────────┘                           │                          │
                                          │  Montoya API:            │
                                          │  - scanner.startAudit()  │
                                          │  - scanner.issues()      │
                                          │  - http.sendRequest()    │
                                          │  - burpSuite.settings()  │
                                          └──────────────────────────┘
                                                    │
                                          All loaded extensions fire
                                          their scan checks automatically
```

**Key design decision:** We don't call individual extensions directly. We trigger Burp's scanner engine via `startAudit()` on a specific request -- ALL loaded extension scan checks fire automatically. Filter results by extension name after.

Benefits:
- No per-extension adapters
- Install new BApp = automatically available
- Zero maintenance when extensions update

**Ports (no conflicts):**
- `:9876` -- PortSwigger MCP extension (untouched)
- `:9877` -- burp-bridge extension (configurable via extension settings)
- `:8080` -- Burp proxy listener (untouched)

## Kotlin Extension (`burp-bridge.jar`)

### Entry Point

```kotlin
class BurpBridge : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        // 1. Store MontoyaApi reference
        // 2. Start embedded HTTP server on :9877
        // 3. Register unloading handler to shut down server
        // 4. Log startup to Burp output tab
    }
}
```

### HTTP API (6 endpoints)

#### GET /api/health
Returns bridge status, Burp version, loaded extension count.

Response:
```json
{
  "status": "ok",
  "burp_version": "2026.3.1",
  "extensions_loaded": 12,
  "bridge_version": "1.0.0",
  "port": 9877
}
```

#### GET /api/extensions
Lists all loaded extensions with capability detection.

Query params: `?name=` (substring filter), `?type=` (active/passive/utility)

Response:
```json
{
  "extensions": [
    {
      "name": "Server-Side Prototype Pollution Scanner",
      "loaded": true,
      "has_scan_check": true,
      "type": "active"
    }
  ]
}
```

Capability detection:
- Primary: `burpSuite().exportProjectOptionsAsJson()` for loaded extension list
- Augmented: bundled `extensions.json` registry maps known BApp names to capability tags
- User can extend `extensions.json` for custom/private extensions

#### POST /api/scan
Triggers targeted audit on a specific HTTP request.

Request:
```json
{
  "request": "POST /api/organization HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}",
  "host": "target.com",
  "port": 443,
  "https": true,
  "config": "light"
}
```

`config` values map to `BuiltInAuditConfiguration`:
- `light` -- LIGHT_ACTIVE (fast, low noise)
- `medium` -- MEDIUM_ACTIVE
- `heavy` -- HEAVY_ACTIVE (thorough, noisy)

Response:
```json
{
  "scan_id": "a1b2c3d4",
  "status": "running",
  "target": "POST /api/organization",
  "config": "light",
  "started_at": "2026-04-07T19:30:00Z"
}
```

Implementation:
1. Parse raw HTTP into `HttpRequest` via `HttpRequest.httpRequest(HttpService, ByteArray)`
2. Send through `api.http().sendRequest(httpRequest)` to get a live `HttpRequestResponse`
3. Build audit config: `AuditConfiguration.auditConfiguration(builtInConfig).withRequestResponse(httpRequestResponse)`
4. Start audit: `api.scanner().startAudit(auditConfig)` -- returns `Audit` handle
5. Store `Audit` handle in `ScanManager` keyed by generated scan_id (8 hex chars)
6. Return scan_id immediately (non-blocking). Client polls GET /api/scan/:id for status.

#### GET /api/scan/:id
Poll scan status and progress.

Response:
```json
{
  "scan_id": "a1b2c3d4",
  "status": "running",
  "insertion_points_tested": 3,
  "insertion_points_total": 7,
  "elapsed_seconds": 45,
  "findings_count": 1
}
```

Status values: `running`, `completed`, `cancelled`, `failed`

#### GET /api/findings
All scanner issues, filterable.

Query params: `?scan_id=`, `?severity=` (high/medium/low/info), `?confidence=` (certain/firm/tentative), `?extension=` (substring), `?url=` (substring)

Response:
```json
{
  "count": 2,
  "findings": [
    {
      "name": "Server-side prototype pollution",
      "severity": "high",
      "confidence": "firm",
      "url": "https://target.com/api/organization",
      "method": "POST",
      "detail": "JSON spaces technique detected pollution...",
      "extension": "Server-Side Prototype Pollution Scanner",
      "request": "POST /api/organization ...",
      "response": "HTTP/1.1 200 OK ..."
    }
  ]
}
```

Evidence (request/response) truncated to 10KB each, matching existing MCP server limits.

#### DELETE /api/scan/:id
Cancel a running audit. Returns `{"status": "cancelled"}` or `404` if not found.

### Internal Components

**ScanManager** -- Manages audit lifecycle. ConcurrentHashMap of scan_id -> Audit reference. Generates short IDs (8 hex chars). Polls audit status via `Audit.statusMessage()`. Auto-cleans completed scans after 1 hour.

**FindingsStore** -- Wraps `MontoyaApi.scanner().issues()`. Applies filters. Maps issues to JSON. Tracks which scan_id produced which findings by correlating URL + timestamp.

**ExtensionRegistry** -- Reads loaded extensions from Burp settings JSON. Merges with bundled `extensions.json` for capability tags. Falls back to "unknown" type for unrecognized extensions.

**HttpServer** -- Embedded Ktor (lightweight, Kotlin-native) HTTP server. Single-threaded event loop is fine -- scan operations are async. CORS disabled (localhost only). Request body limit 1MB.

### Dependencies

- `net.portswigger.burp.extensions:montoya-api:2025.5` (compile-only, provided by Burp)
- `io.ktor:ktor-server-netty:2.3.x` (embedded HTTP server, ~3MB)
- `org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.x` (JSON serialization)
- Gradle shadow plugin for fat JAR

### Build

```bash
cd extension && gradle shadowJar
# Output: extension/build/libs/burp-bridge-1.0.0.jar
```

## Go CLI

### Command Structure

```
burp ext list                              # list loaded extensions
burp ext scan <request-file>               # trigger audit from file
burp ext scan --raw "POST /api/org ..."    # inline raw request
burp ext scan --url <url> --method POST    # build request from flags
burp ext scan ... --config heavy           # audit intensity (default: light)
burp ext scan ... --wait                   # block until scan completes
burp ext scan ... --wait --timeout 120s    # block with timeout
burp ext status <scan-id>                  # poll scan progress
burp ext findings                          # all findings
burp ext findings --scan <scan-id>         # from specific scan
burp ext findings --ext "Prototype"        # filter by extension name
burp ext findings --severity high          # filter by severity
burp ext findings --json                   # JSON output (default: table)
burp ext cancel <scan-id>                  # cancel running audit
burp ext health                            # bridge liveness check
```

### Output Format

Default: terse table (matching existing `burp` CLI style).

```
$ burp ext list
EXTENSION                                    LOADED  TYPE     SCAN
Server-Side Prototype Pollution Scanner      yes     active   yes
Param Miner                                  yes     active   yes
Retire.js                                    yes     passive  yes
Autorize                                     yes     utility  no
---
4 extensions, 3 with scan checks

$ burp ext scan request.txt
SCAN a1b2c3d4 -- POST /api/organization -- light audit -- running

$ burp ext status a1b2c3d4
SCAN a1b2c3d4 -- running -- 3/7 insertion points -- 45s elapsed -- 1 finding

$ burp ext findings --scan a1b2c3d4
SEVERITY  CONFIDENCE  EXTENSION                     URL                       NAME
high      firm        PP Scanner                    POST /api/organization    Server-side prototype pollution
info      tentative   Retire.js                     GET /static/js/main.js    Vulnerable JS library
---
2 findings
```

`--json` flag outputs raw JSON from the bridge API (for scripting/piping).

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `BURP_BRIDGE_URL` | `http://127.0.0.1:9877` | Bridge extension address |
| `BURP_BRIDGE_TIMEOUT` | `30s` | HTTP client timeout |

### Bridge Client

Single file: `cli/internal/bridge/client.go`

```go
type BridgeClient struct {
    BaseURL    string
    HTTPClient *http.Client
}

func (c *BridgeClient) Health() (*HealthResponse, error)
func (c *BridgeClient) ListExtensions(filter string) ([]Extension, error)
func (c *BridgeClient) StartScan(req ScanRequest) (*ScanStatus, error)
func (c *BridgeClient) GetScanStatus(id string) (*ScanStatus, error)
func (c *BridgeClient) GetFindings(opts FindingsFilter) (*FindingsResponse, error)
func (c *BridgeClient) CancelScan(id string) error
```

### Build

```bash
cd cli && go build -o ../releases/burp ./
```

## Monorepo Structure

```
burp-bridge/
├── README.md
├── LICENSE (MIT)
├── Makefile
├── cli/
│   ├── cmd/
│   │   ├── root.go
│   │   ├── serve.go              # existing MCP server
│   │   └── ext/
│   │       ├── list.go
│   │       ├── scan.go
│   │       ├── status.go
│   │       ├── findings.go
│   │       ├── cancel.go
│   │       └── health.go
│   ├── internal/
│   │   ├── burp/                 # existing MCP client
│   │   ├── bridge/
│   │   │   └── client.go
│   │   └── tools/                # existing MCP tools
│   ├── go.mod
│   └── go.sum
├── extension/
│   ├── build.gradle.kts
│   ├── src/main/kotlin/com/burpbridge/
│   │   ├── BurpBridge.kt
│   │   ├── HttpServer.kt
│   │   ├── ScanManager.kt
│   │   ├── FindingsStore.kt
│   │   ├── ExtensionRegistry.kt
│   │   └── ApiRoutes.kt
│   └── src/test/kotlin/
├── registry/
│   └── extensions.json
├── releases/                     # gitignored
├── docs/
│   ├── api.md
│   ├── contributing.md
│   └── phantom-integration.md
└── .github/
    └── workflows/
        └── release.yml           # build both artifacts on tag
```

## Build and Install

```bash
make all               # builds cli + extension
make cli               # go build only
make extension         # gradle shadowJar only
make install-ext       # copies jar to ~/BurpSuitePro/extensions/
make release           # tagged GitHub release with both artifacts
```

**User install flow:**
1. Download `burp-bridge.jar` from GitHub releases
2. Burp > Extensions > Add > select `burp-bridge.jar`
3. Verify: bridge tab shows "Listening on :9877"
4. Download `burp` binary (or `go install github.com/you/burp-bridge/cli@latest`)
5. `burp ext health` -- confirms connection

## Error Handling

| Scenario | CLI behavior |
|----------|-------------|
| Bridge not running | `ERROR: bridge unreachable at :9877 -- is burp-bridge.jar loaded?` |
| Burp not running | Bridge can't start -- Burp extension won't load |
| Scan target unreachable | Scan completes with 0 findings, status shows connection error |
| Invalid request format | 400 from bridge, CLI shows `ERROR: invalid request -- <detail>` |
| Scan timeout (--wait) | CLI exits with code 1, prints `TIMEOUT: scan a1b2c3d4 still running after 120s` |

All errors return structured JSON from the bridge: `{"error": "message", "code": "ERROR_CODE"}`.

## Testing Strategy

**Extension:**
- Unit tests for ScanManager, FindingsStore, ExtensionRegistry (mock MontoyaApi)
- Integration test: load extension in Burp, hit API endpoints with curl
- No Burp headless mode needed for unit tests (Montoya interfaces are mockable)

**CLI:**
- Unit tests for bridge client (httptest mock server)
- Unit tests for output formatting
- Integration test: real Burp + loaded extension + CLI end-to-end

## Security

- Bridge listens on `127.0.0.1` only (not `0.0.0.0`)
- No authentication (localhost trust model, same as PortSwigger's MCP extension)
- Request body limit 1MB on bridge
- Response body truncation at 10KB for findings evidence
- No file system access from bridge

## Versioning

Single version for both components. Semver. Version embedded at build time via `-ldflags` (Go) and `build.gradle.kts` (Kotlin). CLI prints version mismatch warning if bridge reports different version.

## Scope Boundaries (v1 vs later)

| Feature | Version |
|---------|---------|
| Extension discovery | v1 |
| Targeted audit triggering | v1 |
| Findings aggregation + filtering | v1 |
| Terse CLI output + JSON mode | v1 |
| Passive scan hooks (extensions auto-process CLI traffic) | v2 |
| Phantom recon integration | v2 |
| Extension configuration | v3 (if needed) |
| BApp Store auto-install | out of scope |
