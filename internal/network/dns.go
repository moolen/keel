package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/miekg/dns"
)

type DNSResolver interface {
	Exchange(context.Context, *dns.Msg) (*dns.Msg, error)
}

type DNSProxy struct {
	Policy   *PolicyEngine
	Tracker  *Tracker
	Resolver DNSResolver
	Summary  *Summary
	Events   *EventLogger
	Now      func() time.Time
}

func (p DNSProxy) HandleQuery(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	if len(query.Question) == 0 {
		return nil, fmt.Errorf("dns query has no question")
	}

	domain := normalizeName(query.Question[0].Name)
	decision := p.Policy.EvaluateDNS(query.Question[0].Name)
	p.Summary.RecordDNS(domain, decision)
	if !decision.Allowed {
		p.Events.Printf("dns", "%s domain=%s rule=%s reason=%s", decisionLabel(decision), domain, decision.Rule, decision.Reason)
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Rcode = dns.RcodeRefused
		return reply, nil
	}

	resolver := p.Resolver
	if resolver == nil {
		resolver = SystemDNSResolver{}
	}
	reply, err := resolver.Exchange(ctx, query)
	if err != nil {
		p.Events.Printf("dns", "upstream_error domain=%s err=%v", domain, err)
		return nil, err
	}
	p.Events.Printf("dns", "%s domain=%s answers=%d rule=%s reason=%s", decisionLabel(decision), domain, len(reply.Answer), decision.Rule, decision.Reason)

	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	p.observeAnswers(query.Question[0].Name, reply, now)
	return reply, nil
}

func (p DNSProxy) observeAnswers(domain string, reply *dns.Msg, now time.Time) {
	if p.Tracker == nil || reply == nil {
		return
	}
	for _, answer := range reply.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			p.Tracker.Observe(domain, rr.A, time.Duration(rr.Hdr.Ttl)*time.Second, now)
		case *dns.AAAA:
			p.Tracker.Observe(domain, rr.AAAA, time.Duration(rr.Hdr.Ttl)*time.Second, now)
		}
	}
}

func (p DNSProxy) Serve(ctx context.Context, vsockPath string) error {
	socketPath := filepath.Clean(vsockPath) + "_3053"
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return err
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	return p.ServeListener(ctx, listener)
}

func (p DNSProxy) ServeListener(ctx context.Context, listener net.Listener) error {
	defer func() {
		_ = listener.Close()
	}()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer func() {
				_ = conn.Close()
			}()
			_ = p.handleConn(ctx, conn)
		}()
	}
}

func (p DNSProxy) handleConn(ctx context.Context, conn net.Conn) error {
	for {
		payload, err := readDNSPacket(conn)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		query := new(dns.Msg)
		if err := query.Unpack(payload); err != nil {
			return err
		}
		reply, err := p.HandleQuery(ctx, query)
		if err != nil {
			return err
		}
		data, err := reply.Pack()
		if err != nil {
			return err
		}
		if err := writeDNSPacket(conn, data); err != nil {
			return err
		}
	}
}

type SystemDNSResolver struct{}

func (SystemDNSResolver) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	client := dns.Client{Timeout: 5 * time.Second}
	server := "127.0.0.1:53"
	if len(cfg.Servers) > 0 {
		server = net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	reply, _, err := client.ExchangeContext(ctx, msg, server)
	return reply, err
}

func readDNSPacket(r io.Reader) ([]byte, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	buf := make([]byte, int(length))
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeDNSPacket(w io.Writer, payload []byte) error {
	if len(payload) > 0xffff {
		return fmt.Errorf("dns payload too large: %d", len(payload))
	}
	if err := binary.Write(w, binary.BigEndian, uint16(len(payload))); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
