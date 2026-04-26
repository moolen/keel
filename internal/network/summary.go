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
	http   map[HTTPSummaryKey]int
}

func NewSummary() *Summary {
	return &Summary{
		counts: map[summaryKey]int{},
		http:   map[HTTPSummaryKey]int{},
	}
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
	httpRows := make([]httpSummaryRow, 0, len(s.http))
	for key, count := range s.http {
		httpRows = append(httpRows, httpSummaryRow{
			HTTPSummaryKey: key,
			Count:          count,
		})
	}
	s.mu.Unlock()

	if len(rows) == 0 && len(httpRows) == 0 {
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
	sort.Slice(httpRows, func(i, j int) bool {
		left, right := httpRows[i], httpRows[j]
		if left.Host != right.Host {
			return left.Host < right.Host
		}
		if left.Method != right.Method {
			return left.Method < right.Method
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Allowed != right.Allowed {
			return left.Allowed && !right.Allowed
		}
		return false
	})

	if _, err := fmt.Fprintln(w, "Network summary:"); err != nil {
		return err
	}

	for _, row := range rows {
		if row.protocol != "dns" {
			continue
		}
		if _, err := fmt.Fprintf(w, "%-4s %s:%d policy=%s count=%d\n", row.protocol, row.host, row.port, row.policy, row.count); err != nil {
			return err
		}
	}
	for _, row := range httpRows {
		policy := "denied"
		if row.Allowed {
			policy = "allowed"
		}
		if _, err := fmt.Fprintf(w, "http %s %s %s policy=%s count=%d\n", row.Host, row.Method, row.Path, policy, row.Count); err != nil {
			return err
		}
	}
	for _, row := range rows {
		if row.protocol == "dns" {
			continue
		}
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
