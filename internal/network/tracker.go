package network

import (
	"net"
	"sync"
	"time"
)

type trackedAuthorization struct {
	authorization DNSAuthorization
	expiresAt     time.Time
}

type Tracker struct {
	minTTL time.Duration
	mu     sync.RWMutex
	byIP   map[string][]trackedAuthorization
}

func NewTracker(minTTL time.Duration) *Tracker {
	return &Tracker{
		minTTL: minTTL,
		byIP:   map[string][]trackedAuthorization{},
	}
}

func (t *Tracker) ObserveAuthorization(ip net.IP, ttl time.Duration, now time.Time, authorization DNSAuthorization) {
	if ip == nil {
		return
	}
	if ttl < t.minTTL {
		ttl = t.minTTL
	}
	authorization.Host = normalizeName(authorization.Host)

	t.mu.Lock()
	defer t.mu.Unlock()

	key := ip.String()
	t.byIP[key] = append(t.byIP[key], trackedAuthorization{
		authorization: authorization,
		expiresAt:     now.Add(ttl),
	})
}

func (t *Tracker) Authorizations(ip net.IP, port int, now time.Time) []DNSAuthorization {
	if ip == nil {
		return nil
	}
	key := ip.String()

	t.mu.Lock()
	defer t.mu.Unlock()

	entries := t.byIP[key]
	filtered := entries[:0]
	authorizations := make([]DNSAuthorization, 0, len(entries))
	for _, entry := range entries {
		if now.After(entry.expiresAt) {
			continue
		}
		filtered = append(filtered, entry)
		if entry.authorization.Port == port {
			authorizations = append(authorizations, entry.authorization)
		}
	}
	if len(filtered) == 0 {
		delete(t.byIP, key)
	} else {
		t.byIP[key] = filtered
	}
	return authorizations
}

func (t *Tracker) Host(ip net.IP, port int, now time.Time) string {
	authorizations := t.Authorizations(ip, port, now)
	if len(authorizations) == 0 {
		return ""
	}
	return authorizations[0].Host
}
