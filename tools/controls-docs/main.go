// Command controls-docs generates the control reference site published via
// GitHub Pages. It reads the built-in controls and writes one Markdown page
// per control plus an index, into a directory consumed by a static site
// generator (or served as raw Markdown).
//
// The page slug matches scanner.GuideURL: controls/<lowercased-id>/index.md,
// so the CLI's "Guide:" link resolves to the generated page.
//
// Usage:
//
//	go run ./tools/controls-docs [-out site/controls]
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/edgarsilva948/ackrocheck/controls"
	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

func main() {
	out := flag.String("out", "site/controls", "output directory for the generated control pages")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "controls-docs: %v\n", err)
		os.Exit(1)
	}
}

func run(out string) error {
	policies, err := controls.Builtin()
	if err != nil {
		return fmt.Errorf("loading controls: %w", err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	for i := range policies {
		p := &policies[i]
		dir := filepath.Join(out, strings.ToLower(p.ID))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "index.md"), []byte(controlPage(p)), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", p.ID, err)
		}
	}
	if err := os.WriteFile(filepath.Join(out, "index.md"), []byte(indexPage(policies)), 0o644); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d control pages + index to %s\n", len(policies), out)
	return nil
}

func controlPage(p *policy.Policy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", p.ID)
	fmt.Fprintf(&b, "**%s**\n\n", p.Title)
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Severity | %s |\n", p.Severity)
	if p.Category != "" {
		fmt.Fprintf(&b, "| Category | %s |\n", p.Category)
	}
	if p.Resource.Service != "" {
		fmt.Fprintf(&b, "| Service | %s |\n", p.Resource.Service)
	}
	if len(p.Match.Kinds) > 0 {
		fmt.Fprintf(&b, "| Kinds | %s |\n", strings.Join(p.Match.Kinds, ", "))
	}
	if p.Compatibility.Status != "" {
		fmt.Fprintf(&b, "| Status | %s |\n", p.Compatibility.Status)
	}
	b.WriteString("\n")

	if p.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", strings.TrimSpace(p.Description))
	}

	if p.Remediation.Message != "" || len(p.Remediation.Patch) > 0 {
		b.WriteString("## How to fix\n\n")
		if p.Remediation.Message != "" {
			fmt.Fprintf(&b, "%s\n\n", strings.TrimSpace(p.Remediation.Message))
		}
		if patch := renderPatch(p.Remediation.Patch); patch != "" {
			b.WriteString("Apply the following to your manifest:\n\n")
			fmt.Fprintf(&b, "```yaml\n%s\n```\n\n", patch)
		}
	}

	if p.Notes != "" {
		fmt.Fprintf(&b, "## Notes\n\n%s\n\n", strings.TrimSpace(p.Notes))
	}

	if len(p.References) > 0 {
		b.WriteString("## References\n\n")
		for _, r := range p.References {
			if link := referenceLink(r); link != "" {
				fmt.Fprintf(&b, "- %s: [%s](%s)\n", referenceLabel(r.Type), r.ID, link)
			} else {
				fmt.Fprintf(&b, "- %s: %s\n", referenceLabel(r.Type), r.ID)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func indexPage(policies []policy.Policy) string {
	var b strings.Builder
	b.WriteString("# AckroCheck controls\n\n")
	fmt.Fprintf(&b, "%d built-in security controls. Each links to its guide.\n\n", len(policies))
	b.WriteString("| Control | Severity | Title |\n|---|---|---|\n")
	for i := range policies {
		p := &policies[i]
		fmt.Fprintf(&b, "| [%s](%s/) | %s | %s |\n",
			p.ID, strings.ToLower(p.ID), p.Severity, p.Title)
	}
	return b.String()
}

// renderPatch marshals the remediation patch to a YAML snippet (mirrors the
// scanner's unexported helper; duplicated here to keep the tool standalone).
func renderPatch(patch map[string]any) string {
	if len(patch) == 0 {
		return ""
	}
	out, err := yaml.Marshal(patch)
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\n")
}

func referenceLabel(t string) string {
	switch t {
	case "aws_security_hub":
		return "AWS Security Hub"
	case "aws_config":
		return "AWS Config rule"
	default:
		return t
	}
}

// referenceLink builds an authoritative AWS docs URL for known reference types.
func referenceLink(r policy.Reference) string {
	switch r.Type {
	case "aws_security_hub":
		// FSBP control IDs look like "S3.1", "EKS.3"; the docs anchor uses
		// the lowercased service and the full id.
		service := strings.ToLower(strings.SplitN(r.ID, ".", 2)[0])
		return fmt.Sprintf("https://docs.aws.amazon.com/securityhub/latest/userguide/%s-controls.html", service)
	case "aws_config":
		return fmt.Sprintf("https://docs.aws.amazon.com/config/latest/developerguide/%s.html", r.ID)
	default:
		return ""
	}
}
