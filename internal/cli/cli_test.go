package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testdata(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

// runCmd executes the root command with args and returns stdout, stderr, err.
func runCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func TestVersionCommand(t *testing.T) {
	stdout, _, err := runCmd(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"AckroCheck version: dev",
		"Controls version: embedded-dev",
		"Commit: unknown",
		"Build date: unknown",
		"Go version: go",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("version output missing %q:\n%s", want, stdout)
		}
	}
}

func TestScanFailFixturesExitCode(t *testing.T) {
	// Default --fail-on high: insecure fixtures must produce a findings error.
	if code := Execute([]string{"scan", testdata("fail"), "--quiet", "--no-color"}); code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}
}

func TestScanPassFixturesExitCode(t *testing.T) {
	if code := Execute([]string{"scan", testdata("pass"), "--quiet", "--no-color"}); code != ExitOK {
		t.Errorf("exit code = %d, want %d", code, ExitOK)
	}
}

func TestScanFailOnNone(t *testing.T) {
	if code := Execute([]string{"scan", testdata("fail"), "--fail-on", "none", "--quiet", "--no-color"}); code != ExitOK {
		t.Errorf("exit code = %d, want %d", code, ExitOK)
	}
}

func TestScanFailOnCritical(t *testing.T) {
	// RDS fixture has HIGH at most: must pass with --fail-on critical.
	if code := Execute([]string{"scan", testdata("fail", "rds_insecure.yaml"), "--fail-on", "critical", "--quiet", "--no-color"}); code != ExitOK {
		t.Errorf("exit code = %d, want %d", code, ExitOK)
	}
	// S3 fixture has a CRITICAL (public bucket policy).
	if code := Execute([]string{"scan", testdata("fail", "s3_insecure.yaml"), "--fail-on", "critical", "--quiet", "--no-color"}); code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}
}

func TestScanFailOnLow(t *testing.T) {
	if code := Execute([]string{"scan", testdata("fail", "rds_insecure.yaml"), "--fail-on", "low", "--quiet", "--no-color"}); code != ExitFindings {
		t.Errorf("exit code = %d, want %d", code, ExitFindings)
	}
}

func TestScanInvalidUsageExitCode(t *testing.T) {
	tests := [][]string{
		{"scan"},                      // missing path
		{"scan", "/nonexistent/path"}, // missing file
		{"scan", testdata("pass"), "--output", "bogus"},
		{"scan", testdata("pass"), "--fail-on", "bogus"},
		{"scan", testdata("pass"), "--severity", "bogus"},
		{"scan", testdata("pass"), "--framework", "bogus"},
	}
	for _, args := range tests {
		if code := Execute(args); code != ExitError {
			t.Errorf("Execute(%v) = %d, want %d", args, code, ExitError)
		}
	}
}

func TestScanCLIOutput(t *testing.T) {
	stdout, _, err := runCmd(t, "scan", testdata("fail", "rds_insecure.yaml"), "--no-color")
	if err == nil {
		t.Fatal("expected findings error")
	}
	for _, want := range []string{
		"FAILED ACKRO_AWS_RDS_001 HIGH",
		"Resource: rds.services.k8s.aws/v1alpha1 DBInstance insecure-db",
		"Fix: Set spec.storageEncrypted to true.",
		"AckroCheck summary:",
		"Findings: 4",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output missing %q:\n%s", want, stdout)
		}
	}
}

func TestScanJSONOutput(t *testing.T) {
	stdout, _, _ := runCmd(t, "scan", testdata("fail", "rds_insecure.yaml"), "--output", "json")
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if _, ok := decoded["summary"]; !ok {
		t.Error("JSON missing summary")
	}
	if _, ok := decoded["findings"]; !ok {
		t.Error("JSON missing findings")
	}
}

func TestScanSarifToFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "results.sarif")
	stdout, _, _ := runCmd(t, "scan", testdata("fail", "rds_insecure.yaml"),
		"--output", "sarif", "--output-file", outPath)
	if stdout != "" {
		t.Errorf("stdout should be empty when writing to file, got: %s", stdout)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var sarif map[string]interface{}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("SARIF file is not valid JSON: %v", err)
	}
	if sarif["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v", sarif["version"])
	}
}

func TestScanJUnitToFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "results.xml")
	runCmd(t, "scan", testdata("fail", "rds_insecure.yaml"), "--output", "junit", "--output-file", outPath)
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "<testsuites") {
		t.Errorf("JUnit file content: %s", data)
	}
}

func TestScanSeverityFlag(t *testing.T) {
	stdout, _, _ := runCmd(t, "scan", testdata("fail", "rds_insecure.yaml"),
		"--severity", "high", "--no-color")
	if strings.Contains(stdout, "MEDIUM") {
		t.Errorf("medium findings should be filtered:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Findings: 2") {
		t.Errorf("expected 2 findings:\n%s", stdout)
	}
}

func TestScanFrameworkFlag(t *testing.T) {
	stdout, _, err := runCmd(t, "scan", testdata("kro"), "--framework", "ack", "--no-color")
	if err != nil {
		t.Fatalf("KRO RGDs skipped under --framework ack, expected no findings: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Resources scanned: 0") {
		t.Errorf("expected 0 resources scanned:\n%s", stdout)
	}

	stdout, _, _ = runCmd(t, "scan", testdata("kro"), testdata("fail", "rds_insecure.yaml"),
		"--framework", "ack,kro", "--quiet", "--no-color")
	if !strings.Contains(stdout, "Resources scanned: 4") {
		t.Errorf("expected 4 resources scanned with both frameworks:\n%s", stdout)
	}
}

func TestScanQuietAndVerbose(t *testing.T) {
	stdout, stderr, _ := runCmd(t, "scan", testdata("fail", "rds_insecure.yaml"),
		"--quiet", "--verbose", "--no-color")
	if strings.Contains(stdout, "FAILED") {
		t.Error("quiet should suppress findings")
	}
	if !strings.Contains(stderr, "Loaded") {
		t.Errorf("verbose should log to stderr, got: %s", stderr)
	}
}

func TestScanMalformedContinues(t *testing.T) {
	stdout, _, err := runCmd(t, "scan", testdata("malformed"), testdata("pass", "rds_secure.yaml"), "--no-color")
	if err != nil {
		t.Fatalf("malformed file should not fail the scan: %v", err)
	}
	if !strings.Contains(stdout, "PARSE ERROR") {
		t.Errorf("expected parse error in output:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Parse errors: 1") {
		t.Errorf("expected parse error count in summary:\n%s", stdout)
	}
}

func TestScanExternalControls(t *testing.T) {
	dir := t.TempDir()
	external := `id: ACKRO_CUSTOM_001
title: DBInstance must use a custom parameter group
severity: low
match:
  apiGroups: [rds.services.k8s.aws]
  kinds: [DBInstance]
assertions:
  - path: spec.dbParameterGroupName
    operator: exists
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(external), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, _, _ := runCmd(t, "scan", testdata("pass", "rds_secure.yaml"),
		"--external-controls", dir, "--no-color", "--fail-on", "none")
	if !strings.Contains(stdout, "ACKRO_CUSTOM_001") {
		t.Errorf("external control did not run:\n%s", stdout)
	}
}

func TestScanExternalControlsCannotOverrideBuiltin(t *testing.T) {
	dir := t.TempDir()
	override := `id: ACKRO_AWS_RDS_001
title: malicious override
severity: info
match:
  apiGroups: [rds.services.k8s.aws]
  kinds: [DBInstance]
assertions:
  - path: spec.engine
    operator: exists
`
	if err := os.WriteFile(filepath.Join(dir, "override.yaml"), []byte(override), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCmd(t, "scan", testdata("pass"), "--external-controls", dir)
	if err == nil || !strings.Contains(err.Error(), "redefines") {
		t.Fatalf("expected override rejection, got %v", err)
	}
}

func TestScanInvalidExternalControls(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("id: [broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Execute([]string{"scan", testdata("pass"), "--external-controls", dir}); code != ExitError {
		t.Errorf("exit code = %d, want %d", code, ExitError)
	}
}

func TestControlsList(t *testing.T) {
	stdout, _, err := runCmd(t, "controls", "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ID", "ACKRO_AWS_RDS_001", "ACKRO_AWS_S3_001", "ACKRO_AWS_IAM_003"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("controls list missing %q", want)
		}
	}
}

func TestControlsShow(t *testing.T) {
	stdout, _, err := runCmd(t, "controls", "show", "ACKRO_AWS_RDS_001")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"id: ACKRO_AWS_RDS_001", "severity: HIGH", "storageEncrypted"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("controls show missing %q:\n%s", want, stdout)
		}
	}
}

func TestControlsShowCaseInsensitive(t *testing.T) {
	stdout, _, err := runCmd(t, "controls", "show", "ackro_aws_rds_001")
	if err != nil || !strings.Contains(stdout, "id: ACKRO_AWS_RDS_001") {
		t.Errorf("lowercase lookup failed: %v", err)
	}
}

func TestControlsShowNotFound(t *testing.T) {
	_, _, err := runCmd(t, "controls", "show", "ACKRO_NOPE_999")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got %v", err)
	}
	if code := Execute([]string{"controls", "show", "ACKRO_NOPE_999"}); code != ExitError {
		t.Errorf("exit code = %d, want %d", code, ExitError)
	}
}

func TestUnknownCommandExitCode(t *testing.T) {
	if code := Execute([]string{"bogus-command"}); code != ExitError {
		t.Errorf("exit code = %d, want %d", code, ExitError)
	}
}

func TestHelpOutput(t *testing.T) {
	stdout, _, err := runCmd(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"scan", "controls", "version"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help missing %q", want)
		}
	}
}
