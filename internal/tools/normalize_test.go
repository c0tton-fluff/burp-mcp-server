package tools

import "testing"

func TestNormalizeRawRequest(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "unix line endings",
			in:   "GET / HTTP/1.1\nHost: example.com\n",
			want: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name: "already correct",
			in:   "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name: "missing trailing newlines",
			in:   "GET / HTTP/1.1\r\nHost: example.com",
			want: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name: "single trailing CRLF",
			in:   "POST /login HTTP/1.1\r\nHost: example.com\r\n",
			want: "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name: "mixed line endings",
			in:   "GET / HTTP/1.1\r\nHost: example.com\nAccept: */*\n",
			want: "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
		},
		{
			name: "request with body",
			in:   "POST / HTTP/1.1\nHost: example.com\n\n{\"key\":\"value\"}",
			want: "POST / HTTP/1.1\r\nHost: example.com\r\n\r\n{\"key\":\"value\"}\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRawRequest(tt.in)
			if got != tt.want {
				t.Errorf("normalizeRawRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}
