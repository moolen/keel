package network

import (
	"bytes"
	"strings"
	"testing"
)

func TestSummaryRecordsHTTPRequests(t *testing.T) {
	summary := NewSummary()
	summary.RecordHTTP("api.github.com", "GET", "/repos/*", Decision{Allowed: true, Rule: "allow"})
	summary.RecordHTTP("api.github.com", "GET", "/repos/*", Decision{Allowed: true, Rule: "allow"})

	var buf bytes.Buffer
	if err := summary.WriteReport(&buf); err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "http api.github.com GET /repos/* policy=allowed count=2") {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestSummaryRecordHTTPNormalizesHostPort(t *testing.T) {
	summary := NewSummary()

	summary.RecordHTTP("api.github.com:8443", "GET", "/repos/123", Decision{Allowed: true})
	summary.RecordHTTP("api.github.com", "GET", "/repos/123", Decision{Allowed: true})

	if got := len(summary.http); got != 1 {
		t.Fatalf("len(summary.http) = %d, want 1", got)
	}

	key := HTTPSummaryKey{
		Host:    "api.github.com",
		Method:  "GET",
		Path:    "/repos/123",
		Allowed: true,
	}
	if got := summary.http[key]; got != 2 {
		t.Fatalf("summary.http[%+v] = %d, want 2", key, got)
	}
}

func TestSummaryRecordHTTPNormalizesBracketedIPv6Host(t *testing.T) {
	summary := NewSummary()

	summary.RecordHTTP("[2001:db8::1]:443", "GET", "/", Decision{Allowed: false})
	summary.RecordHTTP("[2001:db8::1]", "GET", "/", Decision{Allowed: false})

	if got := len(summary.http); got != 1 {
		t.Fatalf("len(summary.http) = %d, want 1", got)
	}

	key := HTTPSummaryKey{
		Host:    "2001:db8::1",
		Method:  "GET",
		Path:    "/",
		Allowed: false,
	}
	if got := summary.http[key]; got != 2 {
		t.Fatalf("summary.http[%+v] = %d, want 2", key, got)
	}
}
