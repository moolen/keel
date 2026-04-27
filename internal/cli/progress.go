package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

const (
	startupProgressTitle    = "keel preparing vm"
	startupProgressBarWidth = 28
)

type startupStep struct {
	Index   int
	Total   int
	Title   string
	Detail  string
	Current int64
	Target  int64
}

func (s startupStep) WithProgress(current, target int64, detail string) startupStep {
	s.Current = current
	s.Target = target
	if strings.TrimSpace(detail) != "" {
		s.Detail = detail
	}
	return s
}

func (s startupStep) Complete(detail string) startupStep {
	return s.WithProgress(1, 1, detail)
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
type progressPulseMsg struct{}

type progressModel struct {
	bar    progress.Model
	width  int
	title  string
	step   startupStep
	pulse  int
	quited bool
}

var startupProgressPulsePattern = []float64{0.08, 0.16, 0.24, 0.16}

func newProgressModel(total int) progressModel {
	bar := progress.New(progress.WithWidth(startupProgressBarWidth), progress.WithoutPercentage())
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
	return progressPulseCmd()
}

func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch item := msg.(type) {
	case startupStep:
		m.step = item
		if startupStepHasProgress(item) {
			return m, m.bar.SetPercent(startupStepPercent(item))
		}
		return m, m.bar.SetPercent(startupProgressPulsePattern[m.pulse%len(startupProgressPulsePattern)])
	case progress.FrameMsg:
		model, cmd := m.bar.Update(item)
		bar, ok := model.(progress.Model)
		if ok {
			m.bar = bar
		}
		return m, cmd
	case progressPulseMsg:
		if m.quited {
			return m, nil
		}
		if startupStepHasProgress(m.step) {
			return m, progressPulseCmd()
		}
		m.pulse = (m.pulse + 1) % len(startupProgressPulsePattern)
		return m, tea.Batch(
			m.bar.SetPercent(startupProgressPulsePattern[m.pulse]),
			progressPulseCmd(),
		)
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
	return renderStartupProgressView(m.title, m.bar.View(), m.step)
}

func renderStartupProgress(title string, width int, step startupStep) string {
	model := progress.New(progress.WithWidth(width), progress.WithoutPercentage())
	bar := model.ViewAs(startupStepPercent(step))
	return renderStartupProgressView(title, bar, step)
}

func renderStartupProgressView(title, bar string, step startupStep) string {
	lines := []string{
		fmt.Sprintf("%s [%d/%d] %s", title, max(step.Index, 0), max(step.Total, 0), step.Title),
		startupProgressBarLine(bar, step),
	}
	if detail := strings.TrimSpace(step.Detail); detail != "" {
		lines = append(lines, detail)
	}
	return strings.Join(lines, "\n")
}

func startupStepPercent(step startupStep) float64 {
	if step.Target <= 0 {
		return 0
	}
	current := step.Current
	if current < 0 {
		current = 0
	}
	if current > step.Target {
		current = step.Target
	}
	return float64(current) / float64(step.Target)
}

func startupStepHasProgress(step startupStep) bool {
	return step.Target > 0
}

func startupProgressBarLine(bar string, step startupStep) string {
	if !startupStepHasProgress(step) {
		return bar
	}
	return fmt.Sprintf("%s %d%%", bar, int(startupStepPercent(step)*100+0.5))
}

func startupProgressLineCount(step startupStep) int {
	if strings.TrimSpace(step.Detail) == "" {
		return 2
	}
	return 3
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
		lastLines: 2,
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

func progressPulseCmd() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg {
		return progressPulseMsg{}
	})
}

func newStartupProgressReporter(output io.Writer, opts startupProgressOptions) progressReporter {
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
	reporter, err := factory(output, startupPhaseTotal)
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
