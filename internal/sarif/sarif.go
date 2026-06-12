// Package sarif renders scan reports as SARIF 2.1.0 for GitHub code scanning.
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
	"github.com/edgarsilva948/ackrocheck/internal/scanner"
)

// Log is the top-level SARIF document.
type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run is a single SARIF run.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the scanner.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the tool driver and its rules.
type Driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	Version        string `json:"version"`
	Rules          []Rule `json:"rules"`
}

// Rule is a SARIF reportingDescriptor.
type Rule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription Message           `json:"shortDescription"`
	FullDescription  Message           `json:"fullDescription,omitempty"`
	Help             Message           `json:"help,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

// Message is a SARIF text message.
type Message struct {
	Text string `json:"text"`
}

// Result is a single SARIF finding.
type Result struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations"`
}

// Location points at the manifest file.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation holds the artifact reference and region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation is a file URI.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region is a line region within the artifact.
type Region struct {
	StartLine int `json:"startLine"`
}

// Write renders the report as SARIF 2.1.0.
func Write(w io.Writer, r *scanner.Report, version string) error {
	rules, ruleIndex := buildRules(r.Findings)
	results := make([]Result, 0, len(r.Findings))
	for _, f := range r.Findings {
		results = append(results, Result{
			RuleID:    f.ControlID,
			RuleIndex: ruleIndex[f.ControlID],
			Level:     level(f),
			Message:   Message{Text: resultText(f)},
			Locations: []Location{{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: toURI(f.FilePath)},
					Region:           region(f),
				},
			}},
		})
	}
	log := Log{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:           "AckroCheck",
				InformationURI: "https://github.com/edgarsilva948/ackrocheck",
				Version:        version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&log); err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}
	return nil
}

func buildRules(findings []scanner.Finding) ([]Rule, map[string]int) {
	byID := map[string]scanner.Finding{}
	for _, f := range findings {
		if _, ok := byID[f.ControlID]; !ok {
			byID[f.ControlID] = f
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]Rule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		f := byID[id]
		rule := Rule{
			ID:               id,
			Name:             ruleName(id),
			ShortDescription: Message{Text: f.Title},
			FullDescription:  Message{Text: f.Title},
			Properties: map[string]string{
				"severity":          string(f.Severity),
				"security-severity": securitySeverity(f.Severity),
				"category":          f.Category,
			},
		}
		if f.Remediation != "" {
			rule.Help = Message{Text: f.Remediation}
		}
		rules = append(rules, rule)
		index[id] = i
	}
	return rules, index
}

// ruleName converts ACKRO_AWS_RDS_001 into AckroAwsRds001 (SARIF rule names
// should be PascalCase identifiers).
func ruleName(id string) string {
	parts := strings.Split(strings.ToLower(id), "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

func level(f scanner.Finding) string {
	if f.Status == scanner.StatusWarning {
		return "warning"
	}
	switch f.Severity {
	case policy.SeverityCritical, policy.SeverityHigh:
		return "error"
	case policy.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps to GitHub's security-severity score scale.
func securitySeverity(s policy.Severity) string {
	switch s {
	case policy.SeverityCritical:
		return "9.5"
	case policy.SeverityHigh:
		return "8.0"
	case policy.SeverityMedium:
		return "5.0"
	case policy.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

func resultText(f scanner.Finding) string {
	text := fmt.Sprintf("%s %s %q: %s", f.ResourceAPIVersion, f.ResourceKind, f.ResourceName, f.Message)
	if f.ParentResourceKind != "" {
		text += fmt.Sprintf(" (embedded in %s %q)", f.ParentResourceKind, f.ParentResourceName)
	}
	if f.Remediation != "" {
		text += " Fix: " + f.Remediation
	}
	return text
}

func region(f scanner.Finding) *Region {
	if f.Line > 0 {
		return &Region{StartLine: f.Line}
	}
	return nil
}

// toURI normalizes path separators to forward slashes. filepath.ToSlash is
// not enough: it only converts the current OS separator, but SARIF URIs must
// use forward slashes even for Windows paths recorded on another OS.
func toURI(path string) string {
	return strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")
}
