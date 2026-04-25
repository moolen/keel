package vsock

import (
	"bytes"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteDataFrame(&buf, []byte("hello")); err != nil {
		t.Fatalf("WriteDataFrame() error = %v", err)
	}
	if err := WriteResizeFrame(&buf, 24, 80); err != nil {
		t.Fatalf("WriteResizeFrame() error = %v", err)
	}
	if err := WriteExitFrame(&buf, 7); err != nil {
		t.Fatalf("WriteExitFrame() error = %v", err)
	}
	if err := WriteSignalFrame(&buf, 2); err != nil {
		t.Fatalf("WriteSignalFrame() error = %v", err)
	}

	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame(data) error = %v", err)
	}
	if frame.Type != MessageData || string(frame.Data) != "hello" {
		t.Fatalf("data frame = %#v", frame)
	}

	frame, err = ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame(resize) error = %v", err)
	}
	if frame.Type != MessageResize || frame.Rows != 24 || frame.Cols != 80 {
		t.Fatalf("resize frame = %#v", frame)
	}

	frame, err = ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame(exit) error = %v", err)
	}
	if frame.Type != MessageExit || frame.Code != 7 {
		t.Fatalf("exit frame = %#v", frame)
	}

	frame, err = ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame(signal) error = %v", err)
	}
	if frame.Type != MessageSignal || frame.Signal != 2 {
		t.Fatalf("signal frame = %#v", frame)
	}

	_, err = ReadFrame(&buf)
	if err != io.EOF {
		t.Fatalf("ReadFrame(EOF) error = %v, want io.EOF", err)
	}
}
