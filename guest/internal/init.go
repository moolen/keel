package internal

import (
	"context"
	"os"
)

func Bootstrap(command []string, env []string) error {
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
	return ServePTY(command, cwd, proxyEnvironment(env))
}
