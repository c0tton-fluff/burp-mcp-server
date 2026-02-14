package tools

import "strings"

// normalizeRawRequest normalizes line endings in a raw HTTP request for Burp.
// Converts all line endings to \r\n and ensures the request ends with \r\n\r\n.
func normalizeRawRequest(raw string) string {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	if !strings.HasSuffix(s, "\r\n\r\n") {
		if strings.HasSuffix(s, "\r\n") {
			s += "\r\n"
		} else {
			s += "\r\n\r\n"
		}
	}
	return s
}
