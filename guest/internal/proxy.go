package internal

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/mdlayher/vsock"
)

const (
	tcpProxyPort = 3128
	tcpProxyAddr = "127.0.0.1:3128"
)

func StartTCPProxy(ctx context.Context) error {
	listener, err := net.Listen("tcp", tcpProxyAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("tcp proxy accept error: %v", err)
				}
				return
			}
			go func() {
				defer conn.Close()
				if err := handleProxyConn(ctx, conn); err != nil && ctx.Err() == nil {
					log.Printf("tcp proxy connection error: %v", err)
				}
			}()
		}
	}()

	return nil
}

func handleProxyConn(ctx context.Context, client net.Conn) error {
	reader := bufio.NewReader(client)
	target, connect, req, err := parseProxyRequest(reader)
	if err != nil {
		return err
	}

	destination, err := resolveDestination(ctx, target)
	if err != nil {
		return err
	}

	upstream, err := vsock.Dial(hostCID, tcpProxyPort, nil)
	if err != nil {
		return err
	}
	defer upstream.Close()

	if err := writeDestinationHeader(upstream, destination); err != nil {
		return err
	}

	if connect {
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return err
		}
	} else {
		if err := writeProxiedRequest(upstream, req); err != nil {
			return err
		}
	}

	if reader.Buffered() > 0 {
		buffered, err := reader.Peek(reader.Buffered())
		if err != nil {
			return err
		}
		if _, err := upstream.Write(buffered); err != nil {
			return err
		}
	}

	return bridgeGuestProxy(client, upstream)
}

func parseProxyRequest(reader *bufio.Reader) (string, bool, *http.Request, error) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return "", false, nil, err
	}

	target := req.Host
	if req.URL != nil && req.URL.Host != "" {
		target = req.URL.Host
	}
	if target == "" {
		return "", false, nil, fmt.Errorf("proxy request missing target host")
	}

	connect := req.Method == http.MethodConnect
	if !strings.Contains(target, ":") {
		port := "80"
		if connect || (req.URL != nil && req.URL.Scheme == "https") {
			port = "443"
		}
		target = net.JoinHostPort(target, port)
	}

	return target, connect, req, nil
}

func writeProxiedRequest(w io.Writer, req *http.Request) error {
	out := req.Clone(req.Context())
	if out.URL != nil {
		out.URL.Scheme = ""
		out.URL.Host = ""
	}
	out.RequestURI = ""
	out.Header.Del("Proxy-Connection")
	return out.Write(w)
}

func resolveDestination(ctx context.Context, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(ip.String(), port), nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no ip addresses resolved for %s", host)
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

func bridgeGuestProxy(client, upstream net.Conn) error {
	errCh := make(chan error, 2)
	go guestCopy(errCh, upstream, client)
	go guestCopy(errCh, client, upstream)

	var firstErr error
	for range 2 {
		err := <-errCh
		if firstErr == nil && err != nil && err != io.EOF && err != net.ErrClosed {
			firstErr = err
		}
	}
	return firstErr
}

func guestCopy(errCh chan<- error, dst net.Conn, src net.Conn) {
	_, err := io.Copy(dst, src)
	guestCloseWrite(dst)
	errCh <- err
}

func guestCloseWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func proxyEnvironment(base []string) []string {
	env := make([]string, 0, len(base)+7)
	skip := map[string]struct{}{
		"HTTP_PROXY":  {},
		"HTTPS_PROXY": {},
		"http_proxy":  {},
		"https_proxy": {},
		"NO_PROXY":    {},
		"no_proxy":    {},
	}
	for _, entry := range base {
		key := entry
		if idx := strings.IndexByte(entry, '='); idx >= 0 {
			key = entry[:idx]
		}
		if _, drop := skip[key]; drop {
			continue
		}
		env = append(env, entry)
	}

	proxyURL := "http://127.0.0.1:3128"
	env = append(env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	)
	return env
}

func writeDestinationHeader(w io.Writer, destination string) error {
	if len(destination) > 0xff {
		return fmt.Errorf("destination header too large: %d", len(destination))
	}
	if _, err := w.Write([]byte{byte(len(destination))}); err != nil {
		return err
	}
	_, err := io.WriteString(w, destination)
	return err
}
