package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/moolen/keel/internal/config"
	"github.com/moolen/keel/internal/hypervisor"
	"github.com/moolen/keel/internal/network"
	"github.com/moolen/keel/internal/vm"
)

type NetworkServices struct {
	DNS     network.DNSProxy
	TCP     network.TCPProxy
	Summary *network.Summary
}

type NetworkStopFunc func()

type NetworkServiceFactory struct {
	EventOutput EventWriter
	LoadMITMCA  func(config.Config) (*network.CA, error)
}

type EventWriter interface {
	Write([]byte) (int, error)
}

func StartUnixNetworkServices(ctx context.Context, cfg config.Config, assets vm.RuntimeAssets) (func(), *network.Summary, error) {
	stop, summary, err := (NetworkServiceFactory{}).StartUnix(ctx, cfg, assets)
	if stop == nil {
		return nil, summary, err
	}
	return func() { stop() }, summary, err
}

func (f NetworkServiceFactory) Build(cfg config.Config) (NetworkServices, error) {
	tracker := network.NewTracker(60 * time.Second)
	summary := network.NewSummary()
	eventOutput := f.EventOutput
	if eventOutput == nil {
		eventOutput = os.Stderr
	}
	events := network.NewEventLogger(eventOutput)
	policyCfg := network.PolicyConfig{
		Audit:     cfg.Network.Audit,
		Endpoints: endpointRulesFromConfig(cfg.Network.Endpoints, cfg.Network.Audit),
		IPRules:   ipRulesFromConfig(cfg.Network.IPRules),
	}
	engine := network.NewPolicyEngine(policyCfg, tracker)
	services := NetworkServices{
		DNS: network.DNSProxy{
			Policy:  engine,
			Summary: summary,
			Events:  events,
		},
		TCP: network.TCPProxy{
			Policy:  engine,
			Summary: summary,
			Events:  events,
		},
		Summary: summary,
	}
	if policyRequiresMITM(policyCfg) {
		loadCA := f.LoadMITMCA
		if loadCA == nil {
			loadCA = loadMITMCA
		}
		ca, err := loadCA(cfg)
		if err != nil {
			return NetworkServices{}, err
		}
		services.TCP.MITM = &network.MITMProxy{
			Enabled: true,
			CA:      ca,
			Summary: summary,
		}
	}
	return services, nil
}

func (f NetworkServiceFactory) StartUnix(ctx context.Context, cfg config.Config, assets vm.RuntimeAssets) (NetworkStopFunc, *network.Summary, error) {
	serviceCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)

	services, err := f.Build(cfg)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	go func() {
		errCh <- services.DNS.Serve(serviceCtx, assets.VSockPath)
	}()
	go func() {
		errCh <- services.TCP.Serve(serviceCtx, assets.VSockPath)
	}()
	socketPaths := []string{
		assets.VSockPath + "_3053",
		assets.VSockPath + "_3128",
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		ready := true
		for _, socketPath := range socketPaths {
			if _, err := os.Stat(socketPath); err != nil {
				ready = false
				break
			}
		}
		if ready {
			return NetworkStopFunc(cancel), services.Summary, nil
		}
		select {
		case err := <-errCh:
			cancel()
			return nil, nil, err
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			return nil, nil, fmt.Errorf("dns proxy did not start in time")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (f NetworkServiceFactory) StartVM(ctx context.Context, cfg config.Config, instance hypervisor.VM) (NetworkStopFunc, *network.Summary, error) {
	serviceCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 2)

	services, err := f.Build(cfg)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	dnsListener, err := instance.VSockListen(3053)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	tcpListener, err := instance.VSockListen(3128)
	if err != nil {
		cancel()
		_ = dnsListener.Close()
		return nil, nil, err
	}

	go func() {
		errCh <- services.DNS.ServeListener(serviceCtx, dnsListener)
	}()
	go func() {
		errCh <- services.TCP.ServeListener(serviceCtx, tcpListener)
	}()

	select {
	case err := <-errCh:
		cancel()
		return nil, nil, err
	default:
	}
	return NetworkStopFunc(cancel), services.Summary, nil
}

func endpointRulesFromConfig(items []config.EndpointConfig, audit bool) []network.EndpointRule {
	rules := make([]network.EndpointRule, 0, len(items))
	for _, item := range items {
		rule := network.EndpointRule{
			Host:            item.Host,
			Port:            item.Port,
			RequireSNIMatch: true,
		}
		if item.TLS != nil {
			rule.RequireSNIMatch = item.TLS.RequireSNIMatch
		}
		if item.MITM != nil {
			rule.MITMRequired = item.MITM.Required
		}
		if item.HTTP != nil {
			rule.HTTP = endpointHTTPPolicyFromConfig(item.Host, *item.HTTP, audit)
		}
		rules = append(rules, rule)
	}
	return rules
}

func endpointHTTPPolicyFromConfig(host string, item config.EndpointHTTPConfig, audit bool) network.HTTPPolicyConfig {
	return network.HTTPPolicyConfig{
		ScopeHost: host,
		Enabled:   true,
		Default:   item.Default,
		Rules:     endpointHTTPRulesFromConfig(item.Rules),
		Audit:     audit,
	}
}

func endpointHTTPRulesFromConfig(items []config.EndpointHTTPRuleConfig) []network.HTTPRule {
	rules := make([]network.HTTPRule, 0, len(items))
	for _, item := range items {
		rules = append(rules, network.HTTPRule{
			Action:  item.Action,
			Methods: append([]string(nil), item.Methods...),
			Paths:   append([]string(nil), item.Paths...),
		})
	}
	return rules
}

func ipRulesFromConfig(items []config.IPRuleConfig) []network.IPRule {
	rules := make([]network.IPRule, 0, len(items))
	for _, item := range items {
		rules = append(rules, network.IPRule{CIDR: item.CIDR, Port: item.Port})
	}
	return rules
}

func policyRequiresMITM(cfg network.PolicyConfig) bool {
	for _, endpoint := range cfg.Endpoints {
		if endpoint.MITMRequired {
			return true
		}
	}
	return false
}

func loadMITMCA(cfg config.Config) (*network.CA, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	caDir := filepath.Join(home, ".local", "share", "keel", "ca")
	return network.LoadOrCreateCA(network.CAOptions{
		Dir:  caDir,
		Name: cfg.Network.MITM.CA.Name,
	})
}
