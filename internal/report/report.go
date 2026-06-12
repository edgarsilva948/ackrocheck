// Package report renders scan reports as human-readable CLI text and JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/edgarsilva948/ackrocheck/internal/scanner"
)

// ANSI colors used by the CLI writer.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBold   = "\033[1m"
)

// CLIOptions configure the human-readable writer.
type CLIOptions struct {
	NoColor bool
	// Quiet suppresses per-finding output and prints only the summary.
	Quiet bool
}

// WriteCLI renders the report as human-readable text.
func WriteCLI(w io.Writer, r *scanner.Report, opts CLIOptions) error {
	red, yellow, bold, reset := colorRed, colorYellow, colorBold, colorReset
	if opts.NoColor {
		red, yellow, bold, reset = "", "", "", ""
	}

	if !opts.Quiet {
		for _, f := range r.Findings {
			statusColor := red
			if f.Status == scanner.StatusWarning {
				statusColor = yellow
			}
			if _, err := fmt.Fprintf(w, "%s%s%s %s %s%s%s\n", statusColor, f.Status, reset, f.ControlID, bold, f.Severity, reset); err != nil {
				return err
			}
			fmt.Fprintf(w, "Resource: %s %s %s\n", f.ResourceAPIVersion, f.ResourceKind, f.ResourceName)
			if f.ParentResourceKind != "" {
				fmt.Fprintf(w, "Embedded in: %s %s\n", f.ParentResourceKind, f.ParentResourceName)
			}
			if f.Line > 0 {
				fmt.Fprintf(w, "File: %s:%d (document %d)\n", f.FilePath, f.Line, f.DocumentIndex)
			} else {
				fmt.Fprintf(w, "File: %s (document %d)\n", f.FilePath, f.DocumentIndex)
			}
			fmt.Fprintf(w, "Reason: %s\n", f.Message)
			if f.Remediation != "" {
				fmt.Fprintf(w, "Fix: %s\n", f.Remediation)
			}
			fmt.Fprintln(w)
		}
		for _, pe := range r.ParseErrors {
			fmt.Fprintf(w, "%sPARSE ERROR%s %s: %s\n\n", yellow, reset, pe.FilePath, pe.Error)
		}
	}

	s := r.Summary
	_, err := fmt.Fprintf(w,
		"AckroCheck summary:\n"+
			"  Files scanned: %d\n"+
			"  Resources scanned: %d\n"+
			"  Findings: %d\n"+
			"  Critical: %d\n"+
			"  High: %d\n"+
			"  Medium: %d\n"+
			"  Low: %d\n"+
			"  Info: %d\n",
		s.FilesScanned, s.ResourcesScanned, s.Findings, s.Critical, s.High, s.Medium, s.Low, s.Info)
	if err != nil {
		return err
	}
	if s.ParseErrors > 0 {
		fmt.Fprintf(w, "  Parse errors: %d\n", s.ParseErrors)
	}
	return nil
}

// WriteJSON renders the report as indented JSON.
func WriteJSON(w io.Writer, r *scanner.Report) error {
	out := *r
	if out.Findings == nil {
		out.Findings = []scanner.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&out); err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}
	return nil
}
