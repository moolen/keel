package main

import (
	"context"
	"errors"
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
		os.Exit(exitCodeForError(err))
	}
}

func exitCodeForError(err error) int {
	if err == nil {
		return 0
	}
	var exitErr interface{ ExitCode() int }
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}
