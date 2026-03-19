package tools

import "testing"

func TestResolveTarget_Defaults(t *testing.T) {
	rt, err := resolveTarget("", 0, nil, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rt.Host != "example.com" || rt.Port != 443 || !rt.UseTLS {
		t.Errorf("got %+v, want host=example.com port=443 tls=true", rt)
	}
}

func TestResolveTarget_HostPort(t *testing.T) {
	rt, err := resolveTarget("example.com:8080", 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if rt.Host != "example.com" || rt.Port != 8080 {
		t.Errorf("got %+v, want host=example.com port=8080", rt)
	}
}

func TestResolveTarget_OverridePort(t *testing.T) {
	rt, err := resolveTarget("example.com:8080", 9999, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if rt.Port != 9999 {
		t.Errorf("port = %d, want 9999 (explicit override)", rt.Port)
	}
}

func TestResolveTarget_NoTLS(t *testing.T) {
	f := false
	rt, err := resolveTarget("example.com", 0, &f, "")
	if err != nil {
		t.Fatal(err)
	}
	if rt.Port != 80 || rt.UseTLS {
		t.Errorf("got %+v, want port=80 tls=false", rt)
	}
}

func TestResolveTarget_NoHost(t *testing.T) {
	_, err := resolveTarget("", 0, nil, "")
	if err == nil {
		t.Error("expected error for missing host")
	}
}

func TestResolveTarget_FallbackToParsedHost(t *testing.T) {
	rt, err := resolveTarget("", 0, nil, "parsed.com")
	if err != nil {
		t.Fatal(err)
	}
	if rt.Host != "parsed.com" {
		t.Errorf("host = %q, want parsed.com", rt.Host)
	}
}

func TestResolveTarget_IPv6(t *testing.T) {
	rt, err := resolveTarget("[::1]:8080", 0, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if rt.Host != "::1" || rt.Port != 8080 {
		t.Errorf("got %+v, want host=::1 port=8080", rt)
	}
}

func TestValidateRawRequest_Empty(t *testing.T) {
	err := validateRawRequest("")
	if err == nil {
		t.Error("expected error for empty raw")
	}
}

func TestValidateRawRequest_TooLarge(t *testing.T) {
	huge := make([]byte, maxRawRequestSize+1)
	err := validateRawRequest(string(huge))
	if err == nil {
		t.Error("expected error for oversized raw")
	}
}

func TestValidateRawRequest_Valid(t *testing.T) {
	err := validateRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
