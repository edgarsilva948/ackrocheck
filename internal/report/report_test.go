package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
	"github.com/edgarsilva948/ackrocheck/internal/scanner"
)

var update = flag.Bool("update", false, "update golden files")

// sampleReport returns a small fixed report used across output format tests.
func sampleReport() *scanner.Report {
	return &scanner.Report{
		Summary: scanner.Summary{
			FilesScanned:     2,
			ResourcesScanned: 3,
			Findings:         2,
			High:             1,
			Medium:           1,
		},
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
				ResourceNamespace:  "apps",
				FilePath:           "manifests/db.yaml",
				DocumentIndex:      0,
				Line:               2,
				Message:            "RDS DBInstance resources should explicitly enable encryption at rest.",
				Remediation:        "Set spec.storageEncrypted to true.",
				References:         []policy.Reference{{Type: "aws_config", ID: "rds-storage-encrypted"}},
			},
			{
				ControlID:            "ACKRO_AWS_RDS_003",
				Title:                "RDS DBInstance should retain backups for at least 7 days",
				Severity:             policy.SeverityMedium,
				Category:             "RESILIENCE",
				Status:               scanner.StatusWarning,
				ResourceAPIVersion:   "rds.services.k8s.aws/v1alpha1",
				ResourceKind:         "DBInstance",
				ResourceName:         "stack-db",
				FilePath:             "manifests/rgd.yaml",
				DocumentIndex:        0,
				Message:              "value is user-controlled via a templated expression",
				Remediation:          "Set spec.backupRetentionPeriod to 7 or more.",
				ParentResourceKind:   "ResourceGraphDefinition",
				ParentResourceName:   "db-stack",
				EmbeddedResourceKind: "DBInstance",
				EmbeddedResourceName: "stack-db",
			},
		},
		ParseErrors: []scanner.ParseIssue{
			{FilePath: "manifests/broken.yaml", Error: "document 0: yaml: mapping values are not allowed in this context"},
		},
	}
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file (run go test ./... -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output does not match golden file %s\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestWriteCLIGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCLI(&buf, sampleReport(), CLIOptions{NoColor: true}); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "report.txt", buf.Bytes())
}

func TestWriteCLIColor(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCLI(&buf, sampleReport(), CLIOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "\033[31m") {
		t.Error("expected red color codes for FAILED")
	}
	if !strings.Contains(out, "\033[33m") {
		t.Error("expected yellow color codes for WARNING")
	}
}

func TestWriteCLIQuiet(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCLI(&buf, sampleReport(), CLIOptions{NoColor: true, Quiet: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "FAILED") {
		t.Error("quiet mode should not print findings")
	}
	if !strings.Contains(out, "AckroCheck summary:") {
		t.Error("quiet mode should print the summary")
	}
}

func TestWriteCLIEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCLI(&buf, &scanner.Report{}, CLIOptions{NoColor: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Findings: 0") {
		t.Errorf("output = %s", buf.String())
	}
	if strings.Contains(buf.String(), "Parse errors") {
		t.Error("should not print parse errors line when there are none")
	}
}

func TestWriteJSONGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "report.json", buf.Bytes())
}

func TestWriteJSONStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Summary  scanner.Summary   `json:"summary"`
		Findings []scanner.Finding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Summary.Findings != 2 || len(decoded.Findings) != 2 {
		t.Errorf("decoded = %+v", decoded)
	}
	if decoded.Findings[1].ParentResourceName != "db-stack" {
		t.Errorf("KRO context lost: %+v", decoded.Findings[1])
	}
}

func TestWriteJSONEmptyFindingsIsArray(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, &scanner.Report{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("empty findings should encode as [], got: %s", buf.String())
	}
}
