package main

import (
	"context"
	"log"
	"os"

	"github.com/moolen/keel/internal/cli"
	"github.com/moolen/keel/internal/config"
)

func main() {
	cmd := cli.NewRootCommand(cli.Dependencies{
		Runner: cli.HostRunner{},
		LoadConfig: func(_ context.Context, opts config.LoadOptions) (config.Config, error) {
			return config.Load(opts)
		},
	})
	if err := cmd.Execute(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
