package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/moolen/keel/internal/vm"
)

type HostRunner struct{}

func (HostRunner) Run(ctx context.Context, req RunRequest) error {
	if req.Config.DryRun {
		out := req.Stdout
		if out == nil {
			out = io.Discard
		}
		_, err := fmt.Fprintf(out,
			"dry-run: image=%s workspace=%s target=%s command=%q\n",
			req.Config.Image,
			req.Config.Workspace.Mount,
			req.Config.Workspace.Target,
			req.Command,
		)
		return err
	}

	machine := vm.NewMachine(req.Config)
	return machine.Run(ctx)
}
