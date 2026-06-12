package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

func newControlsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controls",
		Short: "Inspect built-in security controls",
	}
	cmd.AddCommand(newControlsListCmd())
	cmd.AddCommand(newControlsShowCmd())
	return cmd
}

func newControlsListCmd() *cobra.Command {
	var externalDir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all available controls",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			policies, err := loadPolicies(externalDir)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSEVERITY\tSERVICE\tKINDS\tTITLE")
			for _, p := range policies {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					p.ID, p.Severity, p.Resource.Service, strings.Join(p.Match.Kinds, ","), p.Title)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&externalDir, "external-controls", "", "directory (or file) with additional local YAML controls")
	return cmd
}

func newControlsShowCmd() *cobra.Command {
	var externalDir string
	cmd := &cobra.Command{
		Use:   "show CONTROL_ID",
		Short: "Show the full definition of a control",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policies, err := loadPolicies(externalDir)
			if err != nil {
				return err
			}
			id := strings.ToUpper(strings.TrimSpace(args[0]))
			var found *policy.Policy
			for i := range policies {
				if policies[i].ID == id {
					found = &policies[i]
					break
				}
			}
			if found == nil {
				return fmt.Errorf("control %s not found (run 'ackrocheck controls list' to see available controls)", id)
			}
			data, err := yaml.Marshal(found)
			if err != nil {
				return fmt.Errorf("rendering control: %w", err)
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
	cmd.Flags().StringVar(&externalDir, "external-controls", "", "directory (or file) with additional local YAML controls")
	return cmd
}
