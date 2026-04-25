package network

import (
	"net"
	"sync"
	"time"
)

type trackedDomain struct {
	domain    string
	expiresAt time.Time
}

type Tracker struct {
	minTTL time.Duration
	mu     sync.RWMutex
	byIP   map[string][]trackedDomain
}

func NewTracker(minTTL time.Duration) *Tracker {
	return &Tracker{
		minTTL: minTTL,
		byIP:   map[string][]trackedDomain{},
	}
}

func (t *Tracker) Observe(domain string, ip net.IP, ttl time.Duration, now time.Time) {
	if ip == nil {
		return
	}
	if ttl < t.minTTL {
		ttl = t.minTTL
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	key := ip.String()
	t.byIP[key] = append(t.byIP[key], trackedDomain{
		domain:    normalizeName(domain),
		expiresAt: now.Add(ttl),
	})
}

func (t *Tracker) Domains(ip net.IP, now time.Time) []string {
	if ip == nil {
		return nil
	}
	key := ip.String()

	t.mu.Lock()
	defer t.mu.Unlock()

	entries := t.byIP[key]
	filtered := entries[:0]
	domains := make([]string, 0, len(entries))
	for _, entry := range entries {
		if now.After(entry.expiresAt) {
			continue
		}
		filtered = append(filtered, entry)
		domains = append(domains, entry.domain)
	}
	if len(filtered) == 0 {
		delete(t.byIP, key)
	} else {
		t.byIP[key] = filtered
	}
	return domains
}
