package scanner

import (
	"sort"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

// Status of a finding.
const (
	StatusFailed = "FAILED"
	// StatusWarning marks best-effort results, e.g. templated KRO fields that
	// cannot be statically verified.
	StatusWarning = "WARNING"
)

// Finding is a single control violation (or warning) on a resource.
type Finding struct {
	ControlID          string             `json:"control_id"`
	Title              string             `json:"title"`
	Severity           policy.Severity    `json:"severity"`
	Category           string             `json:"category"`
	Status             string             `json:"status"`
	ResourceAPIVersion string             `json:"resource_api_version"`
	ResourceKind       string             `json:"resource_kind"`
	ResourceName       string             `json:"resource_name"`
	ResourceNamespace  string             `json:"resource_namespace,omitempty"`
	FilePath           string             `json:"file_path"`
	DocumentIndex      int                `json:"document_index"`
	Line               int                `json:"line,omitempty"`
	Message            string             `json:"message"`
	Remediation        string             `json:"remediation,omitempty"`
	References         []policy.Reference `json:"references,omitempty"`

	// KRO context: set when the finding is on a resource embedded in a
	// ResourceGraphDefinition.
	ParentResourceKind   string `json:"parent_resource_kind,omitempty"`
	ParentResourceName   string `json:"parent_resource_name,omitempty"`
	EmbeddedResourceKind string `json:"embedded_resource_kind,omitempty"`
	EmbeddedResourceName string `json:"embedded_resource_name,omitempty"`
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
	ParseErrors      int `json:"parse_errors"`
}

// Report is the complete result of a scan.
type Report struct {
	Summary     Summary      `json:"summary"`
	Findings    []Finding    `json:"findings"`
	ParseErrors []ParseIssue `json:"parse_errors,omitempty"`
}

// ParseIssue is a file that could not be parsed.
type ParseIssue struct {
	FilePath string `json:"file_path"`
	Error    string `json:"error"`
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
