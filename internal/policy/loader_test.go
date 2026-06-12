package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

const goodPolicyYAML = `id: ACKRO_EXT_001
title: external policy
severity: medium
match:
  apiGroups:
    - rds.services.k8s.aws
  kinds:
    - DBInstance
assertions:
  - path: spec.multiAZ
    operator: is_true
`

func TestLoadFS(t *testing.T) {
	fsys := fstest.MapFS{
		"aws/rds/a.yaml": {Data: []byte(goodPolicyYAML)},
		"aws/rds/multi.yaml": {Data: []byte(`id: ACKRO_EXT_002
title: second
severity: low
match:
  apiGroups: [rds.services.k8s.aws]
  kinds: [DBInstance]
assertions:
  - path: spec.x
    operator: exists
---
id: ACKRO_EXT_003
title: third
severity: high
match:
  apiGroups: [s3.services.k8s.aws]
  kinds: [Bucket]
assertions:
  - path: spec.y
    operator: exists
`)},
		"aws/notes.md": {Data: []byte("not yaml, ignored")},
	}
	policies, err := LoadFS(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 3 {
		t.Fatalf("got %d policies, want 3", len(policies))
	}
	// Sorted by ID.
	for i, want := range []string{"ACKRO_EXT_001", "ACKRO_EXT_002", "ACKRO_EXT_003"} {
		if policies[i].ID != want {
			t.Errorf("policies[%d].ID = %s, want %s", i, policies[i].ID, want)
		}
	}
	if policies[0].Severity != SeverityMedium {
		t.Errorf("severity not normalized: %v", policies[0].Severity)
	}
}

func TestLoadFSInvalidPolicy(t *testing.T) {
	fsys := fstest.MapFS{
		"bad.yaml": {Data: []byte("id: ACKRO_BAD_001\ntitle: no assertions\nseverity: high\nmatch:\n  apiGroups: [x]\n  kinds: [Y]\n")},
	}
	if _, err := LoadFS(fsys, "."); err == nil {
		t.Fatal("expected error for invalid policy")
	}
}

func TestLoadFSDuplicateIDs(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml": {Data: []byte(goodPolicyYAML)},
		"b.yaml": {Data: []byte(goodPolicyYAML)},
	}
	_, err := LoadFS(fsys, ".")
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestLoadFSMalformedYAML(t *testing.T) {
	fsys := fstest.MapFS{
		"bad.yaml": {Data: []byte("id: [unclosed\n")},
	}
	if _, err := LoadFS(fsys, "."); err == nil {
		t.Fatal("expected error for malformed policy YAML")
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ext.yaml"), []byte(goodPolicyYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	policies, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0].ID != "ACKRO_EXT_001" {
		t.Errorf("policies = %+v", policies)
	}
}

func TestLoadDirSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "single.yaml")
	if err := os.WriteFile(path, []byte(goodPolicyYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	policies, err := LoadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Errorf("got %d policies, want 1", len(policies))
	}
}

func TestLoadDirMissing(t *testing.T) {
	if _, err := LoadDir("/nonexistent/controls/dir"); err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestMerge(t *testing.T) {
	builtin := []Policy{{ID: "ACKRO_AWS_RDS_001"}}
	external := []Policy{{ID: "ACKRO_EXT_001"}}
	merged, err := Merge(builtin, external)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 2 {
		t.Errorf("got %d policies, want 2", len(merged))
	}
}

func TestMergeRejectsBuiltinOverride(t *testing.T) {
	builtin := []Policy{{ID: "ACKRO_AWS_RDS_001"}}
	external := []Policy{{ID: "ACKRO_AWS_RDS_001"}}
	_, err := Merge(builtin, external)
	if err == nil || !strings.Contains(err.Error(), "redefines") {
		t.Fatalf("expected override rejection, got %v", err)
	}
}

func TestParsePoliciesSkipsEmptyDocuments(t *testing.T) {
	data := []byte("---\n" + goodPolicyYAML + "\n---\n")
	policies, err := parsePolicies(data, "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Errorf("got %d policies, want 1", len(policies))
	}
}
