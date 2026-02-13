# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-02-13

### Added
- Initial release
- SSE client bridge to Burp Suite MCP extension
- Auto HTTP/2 detection with 15s timeout and HTTP/1.1 fallback
- 2KB default body limit with offset support
- HttpRequestResponse blob unwrapping for clean structured output
- 7 MCP tools replacing Burp's 14+ verbose tools:
  - `burp_send_request` - Unified HTTP send with auto version detection
  - `burp_get_proxy_history` - Proxy history with regex filter and lean summaries
  - `burp_get_scanner_issues` - Structured scanner findings
  - `burp_create_repeater_tab` - Stage request in Repeater
  - `burp_send_to_intruder` - Send request to Intruder
  - `burp_encode` - URL and Base64 encoding
  - `burp_decode` - URL and Base64 decoding
- Pre-built binaries for macOS, Linux, Windows (amd64/arm64)
