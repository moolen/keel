package network

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

type EventLogger struct {
	writer io.Writer
	mu     sync.Mutex
}

func NewEventLogger(writer io.Writer) *EventLogger {
	if writer == nil {
		return nil
	}
	return &EventLogger{writer: writer}
}

func (l *EventLogger) Printf(protocol, format string, args ...any) {
	if l == nil || l.writer == nil {
		return
	}
	message := strings.TrimSpace(fmt.Sprintf(format, args...))
	if message == "" {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = io.WriteString(l.writer, fmt.Sprintf("\n[keel:%s] %s\n", protocol, message))
}
