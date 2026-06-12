// Package cli implements the ackrocheck command-line interface.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/edgarsilva948/ackrocheck/internal/version"
)

// Exit codes. Stable: documented in the README.
const (
	// ExitOK means no findings at or above the fail threshold.
	ExitOK = 0
	// ExitFindings means at least one finding at or above the fail threshold.
	ExitFindings = 1
	// ExitError means a scan error or invalid CLI usage.
	ExitError = 2
)

// NewRootCmd builds the root command with all subcommands attached.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ackrocheck",
		Short: "Checkov-like security checks for AWS ACK and KRO manifests",
		Long: `AckroCheck is a static security scanner for Kubernetes manifests that
define AWS resources through ACK (AWS Controllers for Kubernetes) CRDs and
KRO ResourceGraphDefinitions.

It runs fully offline: no cluster, no AWS credentials, no network access.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCmd())
	root.AddCommand(newControlsCmd())
	root.AddCommand(newVersionCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprint(cmd.OutOrStdout(), version.Get().String())
			return err
		},
	}
}

// Execute runs the CLI and returns a process exit code.
func Execute(args []string) int {
	root := NewRootCmd()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var fe *findingsError
		if asFindingsError(err, &fe) {
			return ExitFindings
		}
		fmt.Fprintf(root.ErrOrStderr(), "Error: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// findingsError signals findings at/above the fail threshold without printing
// an error message (the report already explains everything).
type findingsError struct{ count int }

func (e *findingsError) Error() string {
	return fmt.Sprintf("%d finding(s) at or above the fail threshold", e.count)
}

func asFindingsError(err error, target **findingsError) bool {
	fe, ok := err.(*findingsError)
	if ok {
		*target = fe
	}
	return ok
}
