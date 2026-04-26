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
