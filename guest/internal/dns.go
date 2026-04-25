package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/mdlayher/vsock"
)

const (
	hostCID  = 2
	dnsPort  = 3053
	dnsAddr  = "127.0.0.1:53"
)

func StartDNSForwarder(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", dnsAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("dns forwarder read error: %v", err)
				}
				return
			}
			reply, err := forwardDNSQuery(ctx, buf[:n])
			if err != nil {
				log.Printf("dns forwarder upstream error: %v", err)
				continue
			}
			_, _ = pc.WriteTo(reply, addr)
		}
	}()

	return os.WriteFile("/etc/resolv.conf", []byte("nameserver 127.0.0.1\noptions ndots:0\n"), 0o644)
}

func forwardDNSQuery(ctx context.Context, payload []byte) ([]byte, error) {
	conn, err := vsock.Dial(hostCID, dnsPort, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := writeDNSPacket(conn, payload); err != nil {
		return nil, err
	}
	return readDNSPacket(conn)
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
