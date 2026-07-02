/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package threagile

import (
	"fmt"
	"log"
	"os"
)

type DefaultProgressReporter struct {
	Verbose       bool
	SuppressError bool
}

// Diagnostics (progress, warnings) go to stderr so they never corrupt the
// machine-readable output that data-emitting commands (mermaid, paths, sbom,
// coverage, explain, ...) write to stdout for `command > file`.
func (r DefaultProgressReporter) Info(a ...any) {
	if r.Verbose {
		fmt.Fprintln(os.Stderr, a...)
	}
}

func (DefaultProgressReporter) Warn(a ...any) {
	fmt.Fprintln(os.Stderr, a...)
}

func (r DefaultProgressReporter) Error(v ...any) {
	if r.SuppressError {
		r.Warn(v...)
		return
	}
	log.Fatal(v...)
}

func (r DefaultProgressReporter) Infof(format string, a ...any) {
	if r.Verbose {
		fmt.Fprintf(os.Stderr, format, a...)
		fmt.Fprintln(os.Stderr)
	}
}

func (DefaultProgressReporter) Warnf(format string, a ...any) {
	fmt.Fprint(os.Stderr, "WARNING: ")
	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Fprintln(os.Stderr)
}

func (r DefaultProgressReporter) Errorf(format string, v ...any) {
	if r.SuppressError {
		r.Warnf(format, v...)
		return
	}
	log.Fatalf(format, v...)
}
