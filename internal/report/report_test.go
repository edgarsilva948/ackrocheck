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
				RemediationPatch:   "spec:\n    storageEncrypted: true",
				GuideURL:           "https://edgarsilva948.github.io/ackrocheck/controls/ackro_aws_rds_001/",
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

func TestWriteCLIRemediationAndGuide(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCLI(&buf, sampleReport(), CLIOptions{NoColor: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Apply:") || !strings.Contains(out, "storageEncrypted: true") {
		t.Errorf("expected copy-paste fix block, got:\n%s", out)
	}
	if !strings.Contains(out, "Guide: https://edgarsilva948.github.io/ackrocheck/controls/ackro_aws_rds_001/") {
		t.Errorf("expected guide link, got:\n%s", out)
	}
}

func TestWriteCLIShowPassed(t *testing.T) {
	r := sampleReport()
	r.Passed = []scanner.PassedCheck{
		{ControlID: "ACKRO_AWS_S3_001", Title: "S3 public access block", Severity: policy.SeverityHigh, ResourceKind: "Bucket", ResourceName: "ok-bucket", FilePath: "manifests/s3.yaml"},
	}
	r.Summary.Passed = 1

	// Without ShowPassed: no PASSED lines, no Passed count.
	var off bytes.Buffer
	if err := WriteCLI(&off, r, CLIOptions{NoColor: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off.String(), "PASSED") || strings.Contains(off.String(), "Passed:") {
		t.Errorf("passed checks leaked without ShowPassed:\n%s", off.String())
	}

	// With ShowPassed: PASSED line and count appear.
	var on bytes.Buffer
	if err := WriteCLI(&on, r, CLIOptions{NoColor: true, ShowPassed: true}); err != nil {
		t.Fatal(err)
	}
	out := on.String()
	if !strings.Contains(out, "PASSED ACKRO_AWS_S3_001") {
		t.Errorf("expected PASSED line, got:\n%s", out)
	}
	if !strings.Contains(out, "Passed: 1") {
		t.Errorf("expected passed count in summary, got:\n%s", out)
	}
}

func TestWriteCLIPassedColor(t *testing.T) {
	r := sampleReport()
	r.Passed = []scanner.PassedCheck{{ControlID: "X", Severity: policy.SeverityLow, ResourceKind: "K", ResourceName: "n"}}
	var buf bytes.Buffer
	if err := WriteCLI(&buf, r, CLIOptions{ShowPassed: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\033[32m") {
		t.Error("expected green color codes for PASSED")
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
