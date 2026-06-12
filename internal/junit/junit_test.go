package junit

import (
	"bytes"
	"encoding/xml"
	"flag"
	"os"
	"path/filepath"
	"strings"
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
				Status:             scanner.StatusFailed,
				ResourceAPIVersion: "rds.services.k8s.aws/v1alpha1",
				ResourceKind:       "DBInstance",
				ResourceName:       "app-db",
				FilePath:           "manifests/db.yaml",
				Message:            "RDS DBInstance resources should explicitly enable encryption at rest.",
				Remediation:        "Set spec.storageEncrypted to true.",
			},
			{
				ControlID:            "ACKRO_AWS_RDS_002",
				Title:                "RDS DBInstance should not be publicly accessible",
				Severity:             policy.SeverityHigh,
				Status:               scanner.StatusFailed,
				ResourceKind:         "DBInstance",
				ResourceName:         "stack-db",
				FilePath:             "manifests/rgd.yaml",
				Message:              "publiclyAccessible is true",
				ParentResourceKind:   "ResourceGraphDefinition",
				ParentResourceName:   "db-stack",
				EmbeddedResourceKind: "DBInstance",
				EmbeddedResourceName: "stack-db",
			},
		},
		ParseErrors: []scanner.ParseIssue{
			{FilePath: "manifests/broken.yaml", Error: "yaml: line 3: mapping values are not allowed"},
		},
	}
}

func TestWriteGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "testdata", "golden", "report.xml")
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
		t.Errorf("JUnit output does not match golden file\n--- got ---\n%s", buf.String())
	}
}

func TestWriteStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var suites TestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("output is not valid XML: %v", err)
	}
	if suites.Tests != 3 || suites.Failures != 2 || suites.Errors != 1 {
		t.Errorf("totals: tests=%d failures=%d errors=%d", suites.Tests, suites.Failures, suites.Errors)
	}
	// Suites: two manifest files plus parse-errors, sorted.
	if len(suites.Suites) != 3 {
		t.Fatalf("suites = %d", len(suites.Suites))
	}
	if suites.Suites[0].Name != "manifests/db.yaml" {
		t.Errorf("first suite = %s", suites.Suites[0].Name)
	}
	if suites.Suites[2].Name != "parse-errors" {
		t.Errorf("last suite = %s", suites.Suites[2].Name)
	}
	caseOne := suites.Suites[0].Cases[0]
	if caseOne.Failure == nil || !strings.Contains(caseOne.Failure.Message, "HIGH") {
		t.Errorf("case = %+v", caseOne)
	}
	if !strings.Contains(caseOne.Failure.Body, "Fix: Set spec.storageEncrypted to true.") {
		t.Errorf("body missing remediation: %s", caseOne.Failure.Body)
	}
	// KRO context in body.
	kroCase := suites.Suites[1].Cases[0]
	if !strings.Contains(kroCase.Failure.Body, "Embedded in: ResourceGraphDefinition db-stack") {
		t.Errorf("body missing KRO context: %s", kroCase.Failure.Body)
	}
	// Parse errors are errors, not failures.
	if suites.Suites[2].Cases[0].Error == nil {
		t.Error("parse error case should use <error>")
	}
}

func TestWriteEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, &scanner.Report{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<testsuites") {
		t.Errorf("output = %s", buf.String())
	}
	var suites TestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatal(err)
	}
	if suites.Tests != 0 {
		t.Errorf("tests = %d", suites.Tests)
	}
}
