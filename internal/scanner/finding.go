package scanner

import (
	"sort"
	"strings"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

// guideBaseURL is where the generated control documentation is published.
const guideBaseURL = "https://edgarsilva948.github.io/ackrocheck/controls/"

// GuideURL returns the documentation page URL for a control ID. The docs
// generator (tools/controls-docs) publishes one page per control at the
// matching slug, so the link is stable as long as the control ID is.
func GuideURL(controlID string) string {
	if controlID == "" {
		return ""
	}
	return guideBaseURL + strings.ToLower(controlID) + "/"
}

// Status of a finding.
const (
	StatusFailed = "FAILED"
	// StatusWarning marks best-effort results, e.g. templated KRO fields that
	// cannot be statically verified.
	StatusWarning = "WARNING"
	// StatusPassed marks a control that was evaluated and passed. Passed
	// checks are collected only when Options.IncludePassed is set and are
	// kept separate from Findings so failure-only consumers (SARIF, JUnit,
	// exit codes) are unaffected.
	StatusPassed = "PASSED"
)

// Finding is a single control violation (or warning) on a resource.
type Finding struct {
	ControlID          string          `json:"control_id"`
	Title              string          `json:"title"`
	Severity           policy.Severity `json:"severity"`
	Category           string          `json:"category"`
	Status             string          `json:"status"`
	ResourceAPIVersion string          `json:"resource_api_version"`
	ResourceKind       string          `json:"resource_kind"`
	ResourceName       string          `json:"resource_name"`
	ResourceNamespace  string          `json:"resource_namespace,omitempty"`
	FilePath           string          `json:"file_path"`
	DocumentIndex      int             `json:"document_index"`
	Line               int             `json:"line,omitempty"`
	Message            string          `json:"message"`
	Remediation        string          `json:"remediation,omitempty"`
	// RemediationPatch is the policy's informational fix snippet, rendered as
	// YAML so developers can copy-paste it into their manifest.
	RemediationPatch string `json:"remediation_patch,omitempty"`
	// GuideURL links to the control's documentation page (GitHub Pages).
	GuideURL   string             `json:"guide_url,omitempty"`
	References []policy.Reference `json:"references,omitempty"`

	// KRO context: set when the finding is on a resource embedded in a
	// ResourceGraphDefinition.
	ParentResourceKind   string `json:"parent_resource_kind,omitempty"`
	ParentResourceName   string `json:"parent_resource_name,omitempty"`
	EmbeddedResourceKind string `json:"embedded_resource_kind,omitempty"`
	EmbeddedResourceName string `json:"embedded_resource_name,omitempty"`
}

// PassedCheck is a control that was evaluated against a resource and passed.
// It is intentionally lightweight — passed checks exist for human-readable
// reassurance ("here is what we verified"), not for machine consumers.
type PassedCheck struct {
	ControlID    string          `json:"control_id"`
	Title        string          `json:"title"`
	Severity     policy.Severity `json:"severity"`
	ResourceKind string          `json:"resource_kind"`
	ResourceName string          `json:"resource_name"`
	FilePath     string          `json:"file_path"`
}

// Summary aggregates scan statistics.
type Summary struct {
	FilesScanned     int `json:"files_scanned"`
	ResourcesScanned int `json:"resources_scanned"`
	Findings         int `json:"findings"`
	Critical         int `json:"critical"`
	High             int `json:"high"`
	Medium           int `json:"medium"`
	Low              int `json:"low"`
	Info             int `json:"info"`
	// Passed is the number of control evaluations that passed. It is only
	// populated when the scan collects passed checks.
	Passed      int `json:"passed"`
	ParseErrors int `json:"parse_errors"`
}

// Report is the complete result of a scan.
type Report struct {
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
	// Passed lists controls that passed, populated only when the scan was
	// asked to collect them. Kept separate from Findings so failure-only
	// consumers (SARIF, JUnit, exit codes) never see passed checks.
	Passed      []PassedCheck `json:"passed,omitempty"`
	ParseErrors []ParseIssue  `json:"parse_errors,omitempty"`
}

// ParseIssue is a file that could not be parsed.
type ParseIssue struct {
	FilePath string `json:"file_path"`
	Error    string `json:"error"`
}

// SortPassed orders passed checks deterministically by file, resource, then
// control ID.
func SortPassed(ps []PassedCheck) {
	sort.Slice(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.ResourceName != b.ResourceName {
			return a.ResourceName < b.ResourceName
		}
		return a.ControlID < b.ControlID
	})
}

// SortFindings orders findings by severity (desc), file path, resource name,
// then control ID, for deterministic output.
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.ResourceName != b.ResourceName {
			return a.ResourceName < b.ResourceName
		}
		if a.ControlID != b.ControlID {
			return a.ControlID < b.ControlID
		}
		return a.DocumentIndex < b.DocumentIndex
	})
}
