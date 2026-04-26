package network

import (
	"bytes"
	"strings"
	"testing"
)

func TestSummaryWriteReportAggregatesByHostPortAndDecision(t *testing.T) {
	summary := NewSummary()
	summary.RecordDNS("api.github.com.", Decision{Allowed: true})
	summary.RecordDNS("api.github.com", Decision{Allowed: true})
	summary.RecordHTTP("api.github.com:8443", "get", "/repos/../repos/123?per_page=10", Decision{Allowed: true})
	summary.RecordHTTP("api.github.com", "GET", "/repos/123", Decision{Allowed: true})
	summary.RecordHTTP("[2001:db8::1]:443", "post", "/blocked?debug=1", Decision{Allowed: false})
	summary.RecordTCP("github.com", 443, Decision{Allowed: true})
	summary.RecordTCP("github.com", 443, Decision{Allowed: false})
	summary.RecordTCP("203.0.113.10", 80, Decision{Allowed: false})

	var buf bytes.Buffer
	if err := summary.WriteReport(&buf); err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}

	got := strings.TrimSpace(buf.String())
	want := strings.TrimSpace(`Network summary:
dns  api.github.com:53 policy=allowed count=2
http 2001:db8::1 POST /blocked policy=denied count=1
http api.github.com GET /repos/123 policy=allowed count=2
tcp  203.0.113.10:80 policy=denied count=1
tcp  github.com:443 policy=allowed count=1
tcp  github.com:443 policy=denied count=1`)
	if got != want {
		t.Fatalf("WriteReport() = %q, want %q", got, want)
	}
}

func TestSummaryWriteReportSkipsEmptySummary(t *testing.T) {
	var buf bytes.Buffer
	if err := NewSummary().WriteReport(&buf); err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("WriteReport() output = %q, want empty", buf.String())
	}
}
