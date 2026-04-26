package internal

import (
	"context"
	"net"
	"os"
	"strings"

	guestfeatures "github.com/moolen/keel/guest/internal/features"
	"golang.org/x/sys/unix"
)

func Bootstrap(command []string, env []string, configured []guestfeatures.ConfiguredFeature) error {
	if len(command) == 0 {
		command = []string{"/bin/sh"}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := ensureLoopbackUp(); err != nil {
		return err
	}
	if err := ensureResolverHostname(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := StartDNSForwarder(ctx); err != nil {
		return err
	}
	if err := StartTCPProxy(ctx); err != nil {
		return err
	}
	proxyEnv := proxyEnvironment(env)
	if err := (guestfeatures.Runner{}).RunConfigured(ctx, configured, proxyEnv); err != nil {
		return err
	}
	return ServePTY(command, cwd, proxyEnv)
}

func ensureResolverHostname() error {
	return ensureResolverHostnameWith(os.Hostname, unix.Sethostname)
}

func ensureResolverHostnameWith(getHostname func() (string, error), setHostname func([]byte) error) error {
	hostname, err := getHostname()
	if err != nil {
		return err
	}
	if hostname == "" || net.ParseIP(hostname) != nil || strings.Contains(hostname, ".") {
		return setHostname([]byte("keel"))
	}
	return nil
}
