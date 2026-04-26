package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type stubProgressReporter struct {
	steps   []startupStep
	stopped int
}

func (s *stubProgressReporter) Step(step startupStep) {
	s.steps = append(s.steps, step)
}

func (s *stubProgressReporter) Stop() {
	s.stopped++
}

func TestRenderStartupProgressCompactWithoutDetail(t *testing.T) {
	output := renderStartupProgress(startupProgressTitle, 16, startupStep{
		Index: 3,
		Total: 8,
		Title: "preparing workspace image",
	})

	lines := strings.Split(output, "\n")
	if got, want := len(lines), 3; got != want {
		t.Fatalf("len(lines) = %d, want %d: %q", got, want, output)
	}
	if !strings.Contains(lines[0], "3/8") {
		t.Fatalf("header = %q, want step counter", lines[0])
	}
	if !strings.Contains(lines[1], "38%") {
		t.Fatalf("progress line = %q, want percent", lines[1])
	}
	if got, want := lines[2], "preparing workspace image"; got != want {
		t.Fatalf("step line = %q, want %q", got, want)
	}
}

func TestRenderStartupProgressCompactWithDetail(t *testing.T) {
	output := renderStartupProgress(startupProgressTitle, 16, startupStep{
		Index:  6,
		Total:  10,
		Title:  "preparing workspace image",
		Detail: "pulling files and creating ext4 snapshot",
	})

	lines := strings.Split(output, "\n")
	if got, want := len(lines), 4; got != want {
		t.Fatalf("len(lines) = %d, want %d: %q", got, want, output)
	}
	if got, want := lines[3], "pulling files and creating ext4 snapshot"; got != want {
		t.Fatalf("detail line = %q, want %q", got, want)
	}
}

func TestNewStartupProgressReporterFallsBackForDryRunNonTTYAndFactoryError(t *testing.T) {
	reporter := newStartupProgressReporter(io.Discard, 10, startupProgressOptions{
		DryRun: true,
	})
	if _, ok := reporter.(nopProgressReporter); !ok {
		t.Fatalf("dry-run reporter = %T, want nopProgressReporter", reporter)
	}

	reporter = newStartupProgressReporter(&bytes.Buffer{}, 10, startupProgressOptions{})
	if _, ok := reporter.(nopProgressReporter); !ok {
		t.Fatalf("non-tty reporter = %T, want nopProgressReporter", reporter)
	}

	reporter = newStartupProgressReporter(&bytes.Buffer{}, 10, startupProgressOptions{
		Interactive: func(io.Writer) bool { return true },
		Factory: func(io.Writer, int) (progressReporter, error) {
			return nil, errors.New("boom")
		},
	})
	if _, ok := reporter.(nopProgressReporter); !ok {
		t.Fatalf("factory error reporter = %T, want nopProgressReporter", reporter)
	}
}

func TestNewStartupProgressReporterUsesFactoryWhenInteractive(t *testing.T) {
	expected := &stubProgressReporter{}
	reporter := newStartupProgressReporter(&bytes.Buffer{}, 10, startupProgressOptions{
		Interactive: func(io.Writer) bool { return true },
		Factory: func(io.Writer, int) (progressReporter, error) {
			return expected, nil
		},
	})
	wrapped, ok := reporter.(*stopOnceProgressReporter)
	if !ok {
		t.Fatalf("reporter = %T, want *stopOnceProgressReporter", reporter)
	}
	if wrapped.reporter != expected {
		t.Fatalf("wrapped reporter = %T, want injected reporter", wrapped.reporter)
	}
}

func TestClearRenderedLinesIncludesUpwardCursorMovement(t *testing.T) {
	output := clearRenderedLines(4)
	if !strings.Contains(output, "\x1b[1A") {
		t.Fatalf("clear output = %q, want cursor-up sequence", output)
	}
	if strings.Count(output, "\x1b[2K") != 4 {
		t.Fatalf("clear output = %q, want 4 clear-line sequences", output)
	}
}
