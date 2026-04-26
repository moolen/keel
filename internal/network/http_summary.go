package network

import "strings"

type HTTPSummaryKey struct {
	Host    string
	Method  string
	Path    string
	Allowed bool
}

type httpSummaryRow struct {
	HTTPSummaryKey
	Count int
}

func (s *Summary) RecordHTTP(host, method, path string, decision Decision) {
	if s == nil {
		return
	}

	key := HTTPSummaryKey{
		Host:    normalizeName(host),
		Method:  strings.ToUpper(strings.TrimSpace(method)),
		Path:    normalizeHTTPPath(path),
		Allowed: decision.Allowed,
	}
	if key.Host == "" {
		key.Host = "unknown"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.http[key]++
}
