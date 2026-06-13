// Package report renders scan reports as human-readable CLI text and JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/edgarsilva948/ackrocheck/internal/scanner"
)

// ANSI colors used by the CLI writer.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorDim    = "\033[2m"
	colorBold   = "\033[1m"
)

// CLIOptions configure the human-readable writer.
type CLIOptions struct {
	NoColor bool
	// Quiet suppresses per-finding output and prints only the summary.
	Quiet bool
	// ShowPassed lists controls that passed (Report.Passed) in addition to
	// findings. Has no effect unless the scan collected passed checks.
	ShowPassed bool
}

// palette holds the resolved ANSI codes (empty when --no-color).
type palette struct {
	red, green, yellow, cyan, dim, bold, reset string
}

// WriteCLI renders the report as human-readable text in a Checkov-like layout:
// each finding shows the resource, the exact reason, a copy-paste fix snippet,
// and a link to the control's guide. Passed checks are listed (in green) when
// requested.
func WriteCLI(w io.Writer, r *scanner.Report, opts CLIOptions) error {
	p := palette{colorRed, colorGreen, colorYellow, colorCyan, colorDim, colorBold, colorReset}
	if opts.NoColor {
		p = palette{}
	}

	if !opts.Quiet {
		for _, f := range r.Findings {
			if err := writeFinding(w, f, p); err != nil {
				return err
			}
		}
		if opts.ShowPassed {
			for _, pc := range r.Passed {
				fmt.Fprintf(w, "%sPASSED%s %s %s%s%s  %s%s/%s%s\n",
					p.green, p.reset, pc.ControlID, p.bold, pc.Severity, p.reset,
					p.dim, pc.ResourceKind, pc.ResourceName, p.reset)
			}
			if len(r.Passed) > 0 {
				fmt.Fprintln(w)
			}
		}
		for _, pe := range r.ParseErrors {
			fmt.Fprintf(w, "%sPARSE ERROR%s %s: %s\n\n", p.yellow, p.reset, pe.FilePath, pe.Error)
		}
	}

	return writeSummary(w, r, p, opts)
}

func writeFinding(w io.Writer, f scanner.Finding, p palette) error {
	statusColor := p.red
	if f.Status == scanner.StatusWarning {
		statusColor = p.yellow
	}
	if _, err := fmt.Fprintf(w, "%s%s%s %s %s%s%s  %s%s%s\n",
		statusColor, f.Status, p.reset, f.ControlID, p.bold, f.Severity, p.reset,
		p.dim, f.Title, p.reset); err != nil {
		return err
	}
	fmt.Fprintf(w, "  Resource: %s %s %s\n", f.ResourceAPIVersion, f.ResourceKind, f.ResourceName)
	if f.ParentResourceKind != "" {
		fmt.Fprintf(w, "  Embedded in: %s %s\n", f.ParentResourceKind, f.ParentResourceName)
	}
	if f.Line > 0 {
		fmt.Fprintf(w, "  File: %s:%d (document %d)\n", f.FilePath, f.Line, f.DocumentIndex)
	} else {
		fmt.Fprintf(w, "  File: %s (document %d)\n", f.FilePath, f.DocumentIndex)
	}
	fmt.Fprintf(w, "  Reason: %s\n", f.Message)
	if f.Remediation != "" {
		fmt.Fprintf(w, "  %sFix:%s %s\n", p.bold, p.reset, f.Remediation)
	}
	if f.RemediationPatch != "" {
		fmt.Fprintf(w, "  %sApply:%s\n", p.bold, p.reset)
		for line := range strings.SplitSeq(f.RemediationPatch, "\n") {
			fmt.Fprintf(w, "  %s    %s%s\n", p.green, line, p.reset)
		}
	}
	if f.GuideURL != "" {
		fmt.Fprintf(w, "  Guide: %s%s%s\n", p.cyan, f.GuideURL, p.reset)
	}
	fmt.Fprintln(w)
	return nil
}

func writeSummary(w io.Writer, r *scanner.Report, p palette, opts CLIOptions) error {
	s := r.Summary
	_, err := fmt.Fprintf(w,
		"%sAckroCheck summary:%s\n"+
			"  Files scanned: %d\n"+
			"  Resources scanned: %d\n"+
			"  Findings: %d\n"+
			"  Critical: %d\n"+
			"  High: %d\n"+
			"  Medium: %d\n"+
			"  Low: %d\n"+
			"  Info: %d\n",
		p.bold, p.reset,
		s.FilesScanned, s.ResourcesScanned, s.Findings, s.Critical, s.High, s.Medium, s.Low, s.Info)
	if err != nil {
		return err
	}
	if opts.ShowPassed {
		fmt.Fprintf(w, "  %sPassed: %d%s\n", p.green, s.Passed, p.reset)
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
