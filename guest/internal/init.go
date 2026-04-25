package internal

import (
	"context"
	"os"

	guestfeatures "github.com/moolen/keel/guest/internal/features"
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
