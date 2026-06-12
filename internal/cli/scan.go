package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/edgarsilva948/ackrocheck/controls"
	"github.com/edgarsilva948/ackrocheck/internal/junit"
	"github.com/edgarsilva948/ackrocheck/internal/parser"
	"github.com/edgarsilva948/ackrocheck/internal/policy"
	"github.com/edgarsilva948/ackrocheck/internal/report"
	"github.com/edgarsilva948/ackrocheck/internal/sarif"
	"github.com/edgarsilva948/ackrocheck/internal/scanner"
	"github.com/edgarsilva948/ackrocheck/internal/version"
)

type scanOptions struct {
	output      string
	outputFile  string
	failOn      string
	severity    string
	frameworks  []string
	controlsDir string
	quiet       bool
	verbose     bool
	noColor     bool
}

var validOutputs = map[string]bool{"cli": true, "json": true, "sarif": true, "junit": true}

func newScanCmd() *cobra.Command {
	opts := &scanOptions{}
	cmd := &cobra.Command{
		Use:   "scan PATH [PATH...]",
		Short: "Scan manifests for ACK and KRO security findings",
		Long: `Scan recursively reads YAML manifests from the given files or directories,
evaluates AWS ACK resources and KRO ResourceGraphDefinitions against the
built-in security controls, and prints findings.

Exit codes:
  0  no findings at or above the fail threshold
  1  findings at or above the fail threshold
  2  scan error or invalid usage`,
		Example: `  ackrocheck scan ./manifests
  ackrocheck scan ./manifests --output json
  ackrocheck scan ./manifests --output sarif --output-file results.sarif
  ackrocheck scan ./manifests --fail-on medium --severity low
  ackrocheck scan ./manifests --framework ack`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args, opts)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&opts.output, "output", "o", "cli", "output format: cli, json, sarif, junit")
	f.StringVar(&opts.outputFile, "output-file", "", "write the report to a file instead of stdout")
	f.StringVar(&opts.failOn, "fail-on", "high", "minimum severity that causes exit code 1: critical, high, medium, low, none")
	f.StringVar(&opts.severity, "severity", "info", "minimum severity to report: critical, high, medium, low, info")
	f.StringSliceVar(&opts.frameworks, "framework", nil, "frameworks to scan (ack, kro); default: all")
	f.StringVar(&opts.controlsDir, "external-controls", "", "directory (or file) with additional local YAML controls")
	f.BoolVarP(&opts.quiet, "quiet", "q", false, "only print the summary (cli output)")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "print diagnostic details to stderr")
	f.BoolVar(&opts.noColor, "no-color", false, "disable colored output")
	return cmd
}

func runScan(cmd *cobra.Command, paths []string, opts *scanOptions) error {
	outFormat := strings.ToLower(opts.output)
	if !validOutputs[outFormat] {
		return fmt.Errorf("invalid --output %q: expected cli, json, sarif, or junit", opts.output)
	}

	minSeverity, err := policy.ParseSeverity(opts.severity)
	if err != nil {
		return fmt.Errorf("invalid --severity: %w", err)
	}

	failThreshold, failEnabled, err := parseFailOn(opts.failOn)
	if err != nil {
		return err
	}

	frameworks, err := parseFrameworks(opts.frameworks)
	if err != nil {
		return err
	}

	policies, err := loadPolicies(opts.controlsDir)
	if err != nil {
		return err
	}
	if opts.verbose {
		fmt.Fprintf(cmd.ErrOrStderr(), "Loaded %d controls\n", len(policies))
	}

	parsed, err := parser.ParsePaths(paths)
	if err != nil {
		return err
	}
	if opts.verbose {
		for _, pe := range parsed.Errors {
			fmt.Fprintf(cmd.ErrOrStderr(), "Parse error: %v\n", pe)
		}
	}

	sc := scanner.New(policies, scanner.Options{
		Frameworks:  frameworks,
		MinSeverity: minSeverity,
	})
	rep := sc.Scan(parsed)

	if opts.outputFile != "" {
		file, err := os.Create(opts.outputFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		werr := writeReport(file, rep, outFormat, opts)
		cerr := file.Close()
		if werr != nil {
			return werr
		}
		if cerr != nil {
			return fmt.Errorf("writing output file: %w", cerr)
		}
	} else if err := writeReport(cmd.OutOrStdout(), rep, outFormat, opts); err != nil {
		return err
	}

	if failEnabled {
		count := countAtOrAbove(rep, failThreshold)
		if count > 0 {
			return &findingsError{count: count}
		}
	}
	return nil
}

func writeReport(w io.Writer, rep *scanner.Report, format string, opts *scanOptions) error {
	switch format {
	case "cli":
		return report.WriteCLI(w, rep, report.CLIOptions{NoColor: opts.noColor || opts.outputFile != "", Quiet: opts.quiet})
	case "json":
		return report.WriteJSON(w, rep)
	case "sarif":
		return sarif.Write(w, rep, version.Version)
	case "junit":
		return junit.Write(w, rep)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func parseFailOn(s string) (policy.Severity, bool, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "none" {
		return "", false, nil
	}
	sev, err := policy.ParseSeverity(v)
	if err != nil {
		return "", false, fmt.Errorf("invalid --fail-on %q: expected critical, high, medium, low, or none", s)
	}
	return sev, true, nil
}

func parseFrameworks(values []string) ([]scanner.Framework, error) {
	var out []scanner.Framework
	for _, v := range values {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "ack":
			out = append(out, scanner.FrameworkACK)
		case "kro":
			out = append(out, scanner.FrameworkKRO)
		case "":
		default:
			return nil, fmt.Errorf("invalid --framework %q: expected ack or kro", v)
		}
	}
	return out, nil
}

func loadPolicies(externalDir string) ([]policy.Policy, error) {
	builtin, err := controls.Builtin()
	if err != nil {
		return nil, fmt.Errorf("loading built-in controls: %w", err)
	}
	if externalDir == "" {
		return builtin, nil
	}
	external, err := policy.LoadDir(externalDir)
	if err != nil {
		return nil, fmt.Errorf("loading external controls: %w", err)
	}
	return policy.Merge(builtin, external)
}

func countAtOrAbove(rep *scanner.Report, threshold policy.Severity) int {
	count := 0
	for _, f := range rep.Findings {
		if f.Status == scanner.StatusFailed && f.Severity.AtLeast(threshold) {
			count++
		}
	}
	return count
}
