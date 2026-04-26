package internal

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"

	guestfeatures "github.com/moolen/keel/guest/internal/features"
	"golang.org/x/sys/unix"
)

func Bootstrap(command []string, env []string, configured []guestfeatures.ConfiguredFeature, process *ProcessConfig) error {
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
	if err := runGuestTrustHook(); err != nil {
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
	return ServePTY(command, cwd, proxyEnv, process)
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

func runGuestTrustHook() error {
	return runGuestTrustHookWith(os.Stat, func(path string) error {
		cmd := exec.Command("/bin/sh", path)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	})
}

func runGuestTrustHookWith(stat func(string) (os.FileInfo, error), run func(string) error) error {
	const hookPath = "/etc/keel/install-ca.sh"
	if _, err := stat(hookPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return run(hookPath)
}
