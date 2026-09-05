// Package logging writes updater events line-by-line to
// %APPDATA%\WorkstationAgent\logs\updater-YYYYMMDD.log.
//
// Line format:  ISO-8601-Z timestamp | LEVEL | message
//
// A single global Logger is created via New(dir) at process start; the
// destination directory is derived from %APPDATA% by the caller so tests
// can point it at a scratch dir.
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Level string

const (
	INFO  Level = "INFO"
	WARN  Level = "WARN"
	ERROR Level = "ERROR"
)

// Logger is a tiny line-oriented log writer.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
	echo   io.Writer // optional stderr echo
}

// New opens/creates today's log file under dir. If dir is empty, logs
// only to stderr.
func New(dir string) (*Logger, error) {
	l := &Logger{echo: os.Stderr}
	if dir == "" {
		return l, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("logging: mkdir %s: %w", dir, err)
	}
	name := filepath.Join(dir, "updater-"+time.Now().UTC().Format("20060102")+".log")
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("logging: open %s: %w", name, err)
	}
	l.w = f
	l.closer = f
	return l, nil
}

// Close flushes and closes the underlying file (if any).
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

func (l *Logger) write(level Level, msg string) {
	line := fmt.Sprintf("%s | %s | %s\n",
		time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), level, msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w != nil {
		_, _ = l.w.Write([]byte(line))
	}
	if l.echo != nil {
		_, _ = l.echo.Write([]byte(line))
	}
}

// Info logs a formatted INFO line.
func (l *Logger) Info(format string, a ...any) { l.write(INFO, fmt.Sprintf(format, a...)) }

// Warn logs a formatted WARN line.
func (l *Logger) Warn(format string, a ...any) { l.write(WARN, fmt.Sprintf(format, a...)) }

// Error logs a formatted ERROR line.
func (l *Logger) Error(format string, a ...any) { l.write(ERROR, fmt.Sprintf(format, a...)) }

// DisableEcho stops mirroring log lines to stderr (used by tests).
func (l *Logger) DisableEcho() { l.echo = nil }

// DefaultLogsDir returns %APPDATA%\WorkstationAgent\logs, honouring
// PC_AGENT_APPDATA for tests. Never returns empty (falls back to CWD).
func DefaultLogsDir() string {
	if p := os.Getenv("PC_AGENT_APPDATA"); p != "" {
		return filepath.Join(p, "logs")
	}
	if p := os.Getenv("APPDATA"); p != "" {
		return filepath.Join(p, "WorkstationAgent", "logs")
	}
	return "logs"
}
