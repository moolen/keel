package runtime

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
	"github.com/moolen/keel/internal/network"
	"github.com/moolen/keel/internal/vm"
)

func TestNetworkServicesBuildEndpointScopedPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Network.Audit = true
	cfg.Network.MITM.CA.Name = "keel-local-ca"
	cfg.Network.Endpoints = []config.EndpointConfig{{
		Host: "api.github.com",
		Port: 443,
		TLS:  &config.EndpointTLSConfig{RequireSNIMatch: true},
		MITM: &config.EndpointMITMConfig{Required: true},
		HTTP: &config.EndpointHTTPConfig{
			Default: "deny",
			Rules: []config.EndpointHTTPRuleConfig{{
				Action:  "allow",
				Methods: []string{"GET"},
				Paths:   []string{"/repos/*"},
			}},
		},
	}}

	services, err := (NetworkServiceFactory{
		LoadMITMCA: func(config.Config) (*network.CA, error) {
			return &network.CA{CertPEM: []byte("test ca")}, nil
		},
	}).Build(cfg)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if services.Summary == nil {
		t.Fatal("expected summary")
	}
	if services.TCP.MITM == nil {
		t.Fatal("expected MITM proxy to be enabled")
	}

	decision, auths := services.DNS.Policy.EvaluateDNS("api.github.com")
	if !decision.Allowed || len(auths) != 1 || !auths[0].MITMRequired {
		t.Fatalf("endpoint auth = decision %+v auths %+v", decision, auths)
	}
	if got := auths[0].HTTP.ScopeHost; got != "api.github.com" {
		t.Fatalf("endpoint HTTP scope host = %q, want api.github.com", got)
	}
	if got := auths[0].HTTP.Default; got != "deny" {
		t.Fatalf("endpoint HTTP default = %q, want deny", got)
	}
	if len(auths[0].HTTP.Rules) != 1 || auths[0].HTTP.Rules[0].Host != "" || auths[0].HTTP.Rules[0].Methods[0] != "GET" || auths[0].HTTP.Rules[0].Paths[0] != "/repos/*" {
		t.Fatalf("endpoint HTTP rules = %+v", auths[0].HTTP.Rules)
	}

	httpDecision := network.NewHTTPPolicy(auths[0].HTTP).Evaluate(network.HTTPRequest{
		Host:   "outside.example.com",
		Method: "GET",
		Path:   "/repos/keel",
	})
	if !httpDecision.Allowed || !httpDecision.WouldDeny {
		t.Fatalf("http audit decision outside scope = %+v, want allowed+would_deny", httpDecision)
	}
}

func TestNetworkServicesBuildEnablesAuditMode(t *testing.T) {
	cfg := config.Default()
	cfg.Network.Audit = true
	cfg.Network.MITM.CA.Name = "keel-local-ca"
	cfg.Network.Endpoints = []config.EndpointConfig{{
		Host: "api.github.com",
		Port: 443,
		MITM: &config.EndpointMITMConfig{Required: true},
		HTTP: &config.EndpointHTTPConfig{
			Default: "deny",
		},
	}}

	services, err := (NetworkServiceFactory{
		LoadMITMCA: func(config.Config) (*network.CA, error) {
			return &network.CA{CertPEM: []byte("test ca")}, nil
		},
	}).Build(cfg)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	dnsDecision, _ := services.DNS.Policy.EvaluateDNS("gist.github.com")
	if !dnsDecision.Allowed || !dnsDecision.WouldDeny {
		t.Fatalf("dns audit decision = %+v, want allowed+would_deny", dnsDecision)
	}
	if services.TCP.MITM == nil {
		t.Fatal("expected MITM proxy")
	}
	_, auths := services.DNS.Policy.EvaluateDNS("api.github.com")
	if len(auths) != 1 {
		t.Fatalf("endpoint auths = %+v, want one auth", auths)
	}
	httpDecision := network.NewHTTPPolicy(auths[0].HTTP).Evaluate(network.HTTPRequest{
		Host:   "api.github.com",
		Method: "GET",
		Path:   "/private",
	})
	if !httpDecision.Allowed || !httpDecision.WouldDeny {
		t.Fatalf("http audit decision = %+v, want allowed+would_deny", httpDecision)
	}
}

func TestNetworkServicesStartUnixStartsDNSAndTCPProxies(t *testing.T) {
	vsockPath := filepath.Join(t.TempDir(), "keel.vsock")
	stop, summary, err := (NetworkServiceFactory{}).StartUnix(context.Background(), config.Default(), vm.RuntimeAssets{
		VSockPath: vsockPath,
	})
	if err != nil {
		t.Fatalf("StartUnix() error = %v", err)
	}
	defer stop()
	if summary == nil {
		t.Fatal("StartUnix() summary should not be nil")
	}
	for _, socketPath := range []string{vsockPath + "_3053", vsockPath + "_3128"} {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			t.Fatalf("dial %s: %v", socketPath, err)
		}
		_ = conn.Close()
	}
}

func TestNetworkServicesStartVMStartsDNSAndTCPProxies(t *testing.T) {
	instance := &stubHypervisorVM{
		listen: func(port uint32) (net.Listener, error) {
			return (&net.ListenConfig{}).Listen(context.Background(), "unix", filepath.Join(t.TempDir(), "vsock-"+strconv.Itoa(int(port))))
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop, summary, err := (NetworkServiceFactory{}).StartVM(ctx, config.Default(), instance)
	if err != nil {
		t.Fatalf("StartVM() error = %v", err)
	}
	defer stop()
	if summary == nil {
		t.Fatal("StartVM() summary should not be nil")
	}
	if got, want := instance.listenedPorts, []uint32{3053, 3128}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listened ports = %#v, want %#v", got, want)
	}
}

func TestNetworkServicesStartVMStopClosesListeners(t *testing.T) {
	dnsListener := newBlockingListener()
	tcpListener := newBlockingListener()
	listeners := map[uint32]net.Listener{
		3053: dnsListener,
		3128: tcpListener,
	}
	instance := &stubHypervisorVM{
		listen: func(port uint32) (net.Listener, error) {
			return listeners[port], nil
		},
	}

	stop, _, err := (NetworkServiceFactory{}).StartVM(context.Background(), config.Default(), instance)
	if err != nil {
		t.Fatalf("StartVM() error = %v", err)
	}
	stop()

	assertListenerClosed(t, "dns", dnsListener.closed)
	assertListenerClosed(t, "tcp", tcpListener.closed)
}

type stubHypervisorVM struct {
	listen        func(uint32) (net.Listener, error)
	listenedPorts []uint32
}

func (*stubHypervisorVM) Start(context.Context) error { return nil }
func (*stubHypervisorVM) Stop(context.Context) error  { return nil }
func (*stubHypervisorVM) Wait(context.Context) error  { return nil }
func (*stubHypervisorVM) VSockConnect(uint32) (net.Conn, error) {
	server, client := net.Pipe()
	go server.Close()
	return client, nil
}

func (v *stubHypervisorVM) VSockListen(port uint32) (net.Listener, error) {
	v.listenedPorts = append(v.listenedPorts, port)
	if v.listen != nil {
		return v.listen(port)
	}
	return nil, nil
}

var _ hypervisor.VM = (*stubHypervisorVM)(nil)

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingListener() *blockingListener {
	return &blockingListener{closed: make(chan struct{})}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

func (*blockingListener) Addr() net.Addr {
	return stubNetAddr("vsock")
}

type stubNetAddr string

func (a stubNetAddr) Network() string { return string(a) }
func (a stubNetAddr) String() string  { return string(a) }

func assertListenerClosed(t *testing.T, name string, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatalf("%s listener was not closed", name)
	}
}
