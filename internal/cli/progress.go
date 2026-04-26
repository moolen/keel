package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

const (
	startupProgressTitle    = "keel preparing vm"
	startupProgressBarWidth = 28
)

type startupStep struct {
	Index  int
	Total  int
	Title  string
	Detail string
}

type startupProgressOptions struct {
	DryRun      bool
	Interactive func(io.Writer) bool
	Factory     func(io.Writer, int) (progressReporter, error)
}

type progressReporter interface {
	Step(startupStep)
	Stop()
}

type nopProgressReporter struct{}

func (nopProgressReporter) Step(startupStep) {}
func (nopProgressReporter) Stop()            {}

type stopOnceProgressReporter struct {
	reporter progressReporter
	once     sync.Once
}

func (r *stopOnceProgressReporter) Step(step startupStep) {
	r.reporter.Step(step)
}

func (r *stopOnceProgressReporter) Stop() {
	r.once.Do(func() {
		r.reporter.Stop()
	})
}

type progressStopMsg struct{}

type progressModel struct {
	bar    progress.Model
	width  int
	title  string
	step   startupStep
	quited bool
}

func newProgressModel(total int) progressModel {
	bar := progress.New(progress.WithWidth(startupProgressBarWidth))
	return progressModel{
		bar:   bar,
		width: startupProgressBarWidth,
		title: startupProgressTitle,
		step: startupStep{
			Index: 1,
			Total: total,
			Title: "starting",
		},
	}
}

func (m progressModel) Init() tea.Cmd {
	return nil
}

func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch item := msg.(type) {
	case startupStep:
		m.step = item
		return m, nil
	case progressStopMsg:
		m.quited = true
		return m, tea.Quit
	default:
		return m, nil
	}
}

func (m progressModel) View() string {
	if m.quited {
		return ""
	}
	return renderStartupProgress(m.title, m.width, m.step)
}

func renderStartupProgress(title string, width int, step startupStep) string {
	model := progress.New(progress.WithWidth(width))
	percent := startupProgressPercent(step)
	lines := []string{
		fmt.Sprintf("%s %d/%d", title, max(step.Index, 0), max(step.Total, 0)),
		fmt.Sprintf("%s %d%%", model.ViewAs(percent), startupProgressPercentLabel(step)),
		step.Title,
	}
	if detail := strings.TrimSpace(step.Detail); detail != "" {
		lines = append(lines, detail)
	}
	return strings.Join(lines, "\n")
}

func startupProgressPercent(step startupStep) float64 {
	if step.Total <= 0 {
		return 0
	}
	current := step.Index
	if current < 0 {
		current = 0
	}
	if current > step.Total {
		current = step.Total
	}
	return float64(current) / float64(step.Total)
}

func startupProgressPercentLabel(step startupStep) int {
	return int(startupProgressPercent(step)*100 + 0.5)
}

func startupProgressLineCount(step startupStep) int {
	if strings.TrimSpace(step.Detail) == "" {
		return 3
	}
	return 4
}

type bubbleProgressReporter struct {
	program   *tea.Program
	output    io.Writer
	done      chan struct{}
	lastLines int
	stopOnce  sync.Once
}

func newBubbleProgressReporter(output io.Writer, total int) (progressReporter, error) {
	reporter := &bubbleProgressReporter{
		output:    output,
		done:      make(chan struct{}),
		lastLines: 3,
	}
	model := newProgressModel(total)
	reporter.program = tea.NewProgram(
		model,
		tea.WithOutput(output),
		tea.WithInput(nil),
		tea.WithoutSignals(),
	)
	go func() {
		_, _ = reporter.program.Run()
		close(reporter.done)
	}()
	return reporter, nil
}

func (r *bubbleProgressReporter) Step(step startupStep) {
	r.lastLines = startupProgressLineCount(step)
	r.program.Send(step)
}

func (r *bubbleProgressReporter) Stop() {
	r.stopOnce.Do(func() {
		r.program.Send(progressStopMsg{})
		<-r.done
		_, _ = io.WriteString(r.output, clearRenderedLines(r.lastLines))
	})
}

func clearRenderedLines(lines int) string {
	if lines <= 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("\r\x1b[2K")
	for i := 1; i < lines; i++ {
		builder.WriteString("\x1b[1A\r\x1b[2K")
	}
	builder.WriteString("\r")
	return builder.String()
}

func newStartupProgressReporter(output io.Writer, total int, opts startupProgressOptions) progressReporter {
	if opts.DryRun {
		return nopProgressReporter{}
	}
	interactive := opts.Interactive
	if interactive == nil {
		interactive = isInteractiveTerminal
	}
	if !interactive(output) {
		return nopProgressReporter{}
	}
	factory := opts.Factory
	if factory == nil {
		factory = newBubbleProgressReporter
	}
	reporter, err := factory(output, total)
	if err != nil {
		return nopProgressReporter{}
	}
	return &stopOnceProgressReporter{reporter: reporter}
}

func isInteractiveTerminal(output io.Writer) bool {
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}
