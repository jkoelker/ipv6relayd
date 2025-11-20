package testutil

import (
	"log/slog"
	"strings"
	"testing"
)

type tbWriter struct {
	tb testing.TB
}

func (w tbWriter) Write(p []byte) (int, error) {
	w.tb.Helper()

	w.tb.Log(strings.TrimRight(string(p), "\n"))

	return len(p), nil
}

func LoggerFromTB(tb testing.TB) *slog.Logger {
	tb.Helper()

	handler := slog.NewTextHandler(tbWriter{tb: tb}, &slog.HandlerOptions{Level: slog.LevelDebug})

	return slog.New(handler)
}
