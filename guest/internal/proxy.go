package internal

import (
	"bufio"
	"encoding/binary"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

const (
	tcpProxyPort = 3128
	tcpProxyAddr = "127.0.0.1:3128"
)

func StartTCPProxy(ctx context.Context) error {
	if err := ensureTransparentTCPRedirect(); err != nil {
		log.Printf("transparent tcp redirect unavailable: %v", err)
	}

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
	if destination, err := originalDestination(client); err == nil && shouldUseOriginalDestination(destination) {
		upstream, err := connectTCPProxy(destination)
		if err != nil {
			return err
		}
		defer upstream.Close()
		return bridgeGuestProxy(client, upstream)
	}

	reader := bufio.NewReader(client)
	target, connect, req, err := parseProxyRequest(reader)
	if err != nil {
		return err
	}

	destination, err := resolveDestination(ctx, target)
	if err != nil {
		return err
	}

	upstream, err := connectTCPProxy(destination)
	if err != nil {
		return err
	}
	defer upstream.Close()

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

func connectTCPProxy(destination string) (net.Conn, error) {
	upstream, err := vsock.Dial(hostCID, tcpProxyPort, nil)
	if err != nil {
		return nil, err
	}

	if err := writeDestinationHeader(upstream, destination); err != nil {
		_ = upstream.Close()
		return nil, err
	}
	return upstream, nil
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

func shouldUseOriginalDestination(destination string) bool {
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		return false
	}
	if port != strconv.Itoa(tcpProxyPort) {
		return true
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

func originalDestination(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("original destination requires *net.TCPConn, got %T", conn)
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return "", err
	}

	var destination string
	var controlErr error
	if err := rawConn.Control(func(fd uintptr) {
		destination, controlErr = getsockoptOriginalDestination(int(fd))
	}); err != nil {
		return "", err
	}
	if controlErr != nil {
		return "", controlErr
	}
	return destination, nil
}

func getsockoptOriginalDestination(fd int) (string, error) {
	var addr unix.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_IP),
		uintptr(unix.SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return "", errno
	}
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func ensureTransparentTCPRedirect() error {
	conn := &nftables.Conn{}

	if existing, err := conn.ListTableOfFamily("keel", nftables.TableFamilyIPv4); err == nil {
		conn.DelTable(existing)
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "keel",
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	})
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			&expr.Immediate{
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(tcpProxyPort),
			},
			&expr.Redir{
				RegisterProtoMin: 1,
			},
		},
	})
	return conn.Flush()
}
