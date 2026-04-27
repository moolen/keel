package internal

import (
	"bufio"
	"errors"
	"math/bits"
	"strings"
	"testing"
)

func TestProxyEnvironmentSetsLocalProxyVariables(t *testing.T) {
	env := proxyEnvironment([]string{
		"TERM=xterm-256color",
		"HTTPS_PROXY=http://stale-proxy:9999",
	})

	values := envMap(env)
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if got, want := values[key], "http://127.0.0.1:3128"; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if got, want := values["NO_PROXY"], "127.0.0.1,localhost"; got != want {
		t.Fatalf("NO_PROXY = %q, want %q", got, want)
	}
	if got, want := values["DOCKER_CONFIG"], "/etc/docker/client"; got != want {
		t.Fatalf("DOCKER_CONFIG = %q, want %q", got, want)
	}
	if got, want := values["TERM"], "xterm-256color"; got != want {
		t.Fatalf("TERM = %q, want %q", got, want)
	}
}

func TestProxyEnvironmentAddsDefaultPath(t *testing.T) {
	values := envMap(proxyEnvironment(nil))
	if got, want := values["PATH"], "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; got != want {
		t.Fatalf("PATH = %q, want %q", got, want)
	}
}

func TestProxyEnvironmentReplacesEmptyPath(t *testing.T) {
	values := envMap(proxyEnvironment([]string{"PATH="}))
	if got, want := values["PATH"], "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; got != want {
		t.Fatalf("PATH = %q, want %q", got, want)
	}
}

func TestParseConnectDestination(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n"))

	target, connect, req, err := parseProxyRequest(reader)
	if err != nil {
		t.Fatalf("parseProxyRequest() error = %v", err)
	}
	if !connect {
		t.Fatal("expected CONNECT request")
	}
	if target != "api.github.com:443" {
		t.Fatalf("target = %q, want api.github.com:443", target)
	}
	if req == nil {
		t.Fatal("expected parsed request")
	}
}

func TestShouldUseOriginalDestination(t *testing.T) {
	cases := []struct {
		name        string
		destination string
		want        bool
	}{
		{name: "external target", destination: "203.0.113.10:443", want: true},
		{name: "local proxy target", destination: "127.0.0.1:3128", want: false},
		{name: "ipv6 local proxy target", destination: "[::1]:3128", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldUseOriginalDestination(tc.destination); got != tc.want {
				t.Fatalf("shouldUseOriginalDestination(%q) = %v, want %v", tc.destination, got, tc.want)
			}
		})
	}
}

func TestTCPProxyListensOnAllInterfaces(t *testing.T) {
	if got, want := tcpProxyAddr, "0.0.0.0:3128"; got != want {
		t.Fatalf("tcpProxyAddr = %q, want %q", got, want)
	}
}

func TestChooseTrafficInterceptionPrefersBPF(t *testing.T) {
	want := proxyAwareOnlyInterception{}
	bpfCalls := 0
	nftCalls := 0

	got := chooseTrafficInterception(interceptionFactory{
		startBPF: func() (trafficInterception, error) {
			bpfCalls++
			return want, nil
		},
		startNFT: func() (trafficInterception, error) {
			nftCalls++
			return legacyRedirectInterception{}, nil
		},
	})

	if got.mode() != proxyAwareOnlyMode {
		t.Fatalf("mode = %q, want %q", got.mode(), proxyAwareOnlyMode)
	}
	if bpfCalls != 1 {
		t.Fatalf("bpfCalls = %d, want 1", bpfCalls)
	}
	if nftCalls != 0 {
		t.Fatalf("nftCalls = %d, want 0", nftCalls)
	}
}

func TestChooseTrafficInterceptionFallsBackToNFT(t *testing.T) {
	bpfErr := errors.New("bpf unavailable")
	bpfCalls := 0
	nftCalls := 0

	got := chooseTrafficInterception(interceptionFactory{
		startBPF: func() (trafficInterception, error) {
			bpfCalls++
			return nil, bpfErr
		},
		startNFT: func() (trafficInterception, error) {
			nftCalls++
			return legacyRedirectInterception{}, nil
		},
	})

	if got.mode() != legacyRedirectMode {
		t.Fatalf("mode = %q, want %q", got.mode(), legacyRedirectMode)
	}
	if bpfCalls != 1 {
		t.Fatalf("bpfCalls = %d, want 1", bpfCalls)
	}
	if nftCalls != 1 {
		t.Fatalf("nftCalls = %d, want 1", nftCalls)
	}
}

func TestChooseTrafficInterceptionFallsBackToProxyAwareOnly(t *testing.T) {
	got := chooseTrafficInterception(interceptionFactory{
		startBPF: func() (trafficInterception, error) {
			return nil, errors.New("bpf unavailable")
		},
		startNFT: func() (trafficInterception, error) {
			return nil, errors.New("nft unavailable")
		},
	})

	if got.mode() != proxyAwareOnlyMode {
		t.Fatalf("mode = %q, want %q", got.mode(), proxyAwareOnlyMode)
	}
}

func TestFormatBPFOriginalDestination(t *testing.T) {
	got, err := formatBPFOriginalDestination(bpfOriginalDestination{
		IP4:  bits.ReverseBytes32(0xcb00710a),
		Port: uint32(bits.ReverseBytes16(443)),
	})
	if err != nil {
		t.Fatalf("formatBPFOriginalDestination() error = %v", err)
	}
	if want := "203.0.113.10:443"; got != want {
		t.Fatalf("destination = %q, want %q", got, want)
	}
}

func TestStoredNetworkPortUint32(t *testing.T) {
	if got, want := storedNetworkPortUint32(3128), uint32(bits.ReverseBytes16(3128)); got != want {
		t.Fatalf("storedNetworkPortUint32(3128) = %#x, want %#x", got, want)
	}
}

func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, entry := range env {
		if idx := strings.IndexByte(entry, '='); idx >= 0 {
			out[entry[:idx]] = entry[idx+1:]
		}
	}
	return out
}
