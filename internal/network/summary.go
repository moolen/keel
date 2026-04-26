package network

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

type summaryKey struct {
	protocol string
	host     string
	port     int
	policy   string
}

type Summary struct {
	mu     sync.Mutex
	counts map[summaryKey]int
}

func NewSummary() *Summary {
	return &Summary{counts: map[summaryKey]int{}}
}

func (s *Summary) RecordDNS(host string, decision Decision) {
	s.record("dns", host, 53, decision)
}

func (s *Summary) RecordTCP(host string, port int, decision Decision) {
	s.record("tcp", host, port, decision)
}

func (s *Summary) record(protocol, host string, port int, decision Decision) {
	if s == nil {
		return
	}
	host = normalizeName(host)
	if host == "" {
		host = "unknown"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[summaryKey{
		protocol: protocol,
		host:     host,
		port:     port,
		policy:   decisionLabel(decision),
	}]++
}

func (s *Summary) WriteReport(w io.Writer) error {
	if s == nil || w == nil {
		return nil
	}

	s.mu.Lock()
	rows := make([]summaryRow, 0, len(s.counts))
	for key, count := range s.counts {
		rows = append(rows, summaryRow{
			summaryKey: key,
			count:      count,
		})
	}
	s.mu.Unlock()

	if len(rows) == 0 {
		return nil
	}

	sort.Slice(rows, func(i, j int) bool {
		left, right := rows[i], rows[j]
		if left.protocol != right.protocol {
			return left.protocol < right.protocol
		}
		if left.host != right.host {
			return left.host < right.host
		}
		if left.port != right.port {
			return left.port < right.port
		}
		return left.policy < right.policy
	})

	if _, err := fmt.Fprintln(w, "Network summary:"); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(w, "%-4s %s:%d policy=%s count=%d\n", row.protocol, row.host, row.port, row.policy, row.count); err != nil {
			return err
		}
	}
	return nil
}

type summaryRow struct {
	summaryKey
	count int
}

func decisionLabel(decision Decision) string {
	if decision.Allowed {
		return "allowed"
	}
	return "denied"
}
