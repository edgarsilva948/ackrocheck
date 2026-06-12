package sarif

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
	"github.com/edgarsilva948/ackrocheck/internal/scanner"
)

var update = flag.Bool("update", false, "update golden files")

func sampleReport() *scanner.Report {
	return &scanner.Report{
		Findings: []scanner.Finding{
			{
				ControlID:          "ACKRO_AWS_RDS_001",
				Title:              "RDS DBInstance should enable storage encryption",
				Severity:           policy.SeverityHigh,
				Category:           "DATA_PROTECTION",
				Status:             scanner.StatusFailed,
				ResourceAPIVersion: "rds.services.k8s.aws/v1alpha1",
				ResourceKind:       "DBInstance",
				ResourceName:       "app-db",
				FilePath:           "manifests/db.yaml",
				Line:               2,
				Message:            "RDS DBInstance resources should explicitly enable encryption at rest.",
				Remediation:        "Set spec.storageEncrypted to true.",
			},
			{
				ControlID:          "ACKRO_AWS_RDS_001",
				Title:              "RDS DBInstance should enable storage encryption",
				Severity:           policy.SeverityHigh,
				Status:             scanner.StatusFailed,
				ResourceAPIVersion: "rds.services.k8s.aws/v1alpha1",
				ResourceKind:       "DBInstance",
				ResourceName:       "other-db",
				FilePath:           "manifests\\windows\\db.yaml",
				Message:            "RDS DBInstance resources should explicitly enable encryption at rest.",
			},
			{
				ControlID:            "ACKRO_AWS_RDS_003",
				Title:                "RDS DBInstance should retain backups for at least 7 days",
				Severity:             policy.SeverityMedium,
				Status:               scanner.StatusWarning,
				ResourceKind:         "DBInstance",
				ResourceName:         "stack-db",
				FilePath:             "manifests/rgd.yaml",
				Message:              "value is user-controlled",
				ParentResourceKind:   "ResourceGraphDefinition",
				ParentResourceName:   "db-stack",
				EmbeddedResourceKind: "DBInstance",
				EmbeddedResourceName: "stack-db",
			},
		},
	}
}

func TestWriteGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleReport(), "test"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "testdata", "golden", "report.sarif")
	if *update {
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file (run go test ./... -update to create): %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("SARIF output does not match golden file\n--- got ---\n%s", buf.String())
	}
}

func TestWriteStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleReport(), "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var log Log
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %s", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "AckroCheck" || run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	// Two distinct rules despite three results.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "ACKRO_AWS_RDS_001" {
		t.Errorf("rules not sorted: %s", run.Tool.Driver.Rules[0].ID)
	}
	if run.Tool.Driver.Rules[0].Name != "AckroAwsRds001" {
		t.Errorf("rule name = %s", run.Tool.Driver.Rules[0].Name)
	}
	if run.Tool.Driver.Rules[0].Properties["security-severity"] != "8.0" {
		t.Errorf("security-severity = %s", run.Tool.Driver.Rules[0].Properties["security-severity"])
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d", len(run.Results))
	}
	first := run.Results[0]
	if first.Level != "error" {
		t.Errorf("HIGH should map to error, got %s", first.Level)
	}
	if first.RuleIndex != 0 {
		t.Errorf("ruleIndex = %d", first.RuleIndex)
	}
	if first.Locations[0].PhysicalLocation.Region.StartLine != 2 {
		t.Errorf("startLine = %+v", first.Locations[0].PhysicalLocation.Region)
	}
	// Windows path converted to forward slashes.
	second := run.Results[1]
	if second.Locations[0].PhysicalLocation.ArtifactLocation.URI != "manifests/windows/db.yaml" {
		t.Errorf("URI = %s", second.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if second.Locations[0].PhysicalLocation.Region != nil {
		t.Error("no line should mean no region")
	}
	// Warning status maps to warning level regardless of severity.
	third := run.Results[2]
	if third.Level != "warning" {
		t.Errorf("warning status level = %s", third.Level)
	}
}

func TestLevelMapping(t *testing.T) {
	tests := []struct {
		severity policy.Severity
		want     string
	}{
		{policy.SeverityCritical, "error"},
		{policy.SeverityHigh, "error"},
		{policy.SeverityMedium, "warning"},
		{policy.SeverityLow, "note"},
		{policy.SeverityInfo, "note"},
	}
	for _, tt := range tests {
		f := scanner.Finding{Severity: tt.severity, Status: scanner.StatusFailed}
		if got := level(f); got != tt.want {
			t.Errorf("level(%s) = %s, want %s", tt.severity, got, tt.want)
		}
	}
}

func TestSecuritySeverityMapping(t *testing.T) {
	for _, sev := range policy.AllSeverities() {
		if securitySeverity(sev) == "" {
			t.Errorf("no security-severity for %s", sev)
		}
	}
}

func TestWriteEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, &scanner.Report{}, "test"); err != nil {
		t.Fatal(err)
	}
	var log Log
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs[0].Results) != 0 {
		t.Error("empty report should have no results")
	}
}
