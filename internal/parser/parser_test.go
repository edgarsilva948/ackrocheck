package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseMultiDocument(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "multi.yaml", `apiVersion: rds.services.k8s.aws/v1alpha1
kind: DBInstance
metadata:
  name: db-one
  namespace: apps
  labels:
    environment: prod
  annotations:
    ackrocheck.dev/environment: production
spec:
  storageEncrypted: true
---
apiVersion: s3.services.k8s.aws/v1alpha1
kind: Bucket
metadata:
  name: bucket-one
spec:
  name: bucket-one
`)
	resources, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 {
		t.Fatalf("got %d resources, want 2", len(resources))
	}
	first := resources[0]
	if first.Kind != "DBInstance" || first.Name != "db-one" || first.Namespace != "apps" {
		t.Errorf("unexpected first resource: %+v", first)
	}
	if first.APIGroup() != "rds.services.k8s.aws" {
		t.Errorf("APIGroup = %q", first.APIGroup())
	}
	if first.Labels["environment"] != "prod" {
		t.Errorf("labels = %v", first.Labels)
	}
	if first.Annotations["ackrocheck.dev/environment"] != "production" {
		t.Errorf("annotations = %v", first.Annotations)
	}
	if first.DocIndex != 0 || resources[1].DocIndex != 1 {
		t.Errorf("doc indexes: %d, %d", first.DocIndex, resources[1].DocIndex)
	}
	if first.Line != 1 {
		t.Errorf("first doc line = %d, want 1", first.Line)
	}
	if resources[1].Line <= first.Line {
		t.Errorf("second doc line = %d, should be after first", resources[1].Line)
	}
	if v, ok := first.Spec["storageEncrypted"]; !ok || v != true {
		t.Errorf("spec = %v", first.Spec)
	}
}

func TestParseMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "broken.yaml", "apiVersion: x\nkind: y\n  bad: [unclosed\n")
	writeFile(t, dir, "good.yaml", "apiVersion: rds.services.k8s.aws/v1alpha1\nkind: DBInstance\nmetadata:\n  name: ok\n")

	res, err := ParsePaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("got %d parse errors, want 1: %v", len(res.Errors), res.Errors)
	}
	if !strings.Contains(res.Errors[0].FilePath, "broken.yaml") {
		t.Errorf("error path = %s", res.Errors[0].FilePath)
	}
	if res.Errors[0].Error() == "" {
		t.Error("ParseError.Error() should not be empty")
	}
	// Scanning continued: the good file was parsed.
	if len(res.Resources) != 1 || res.Resources[0].Name != "ok" {
		t.Errorf("resources = %+v", res.Resources)
	}
	if res.FilesScanned != 2 {
		t.Errorf("FilesScanned = %d, want 2", res.FilesScanned)
	}
}

func TestParseSkipsNonResourceDocuments(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "mixed.yaml", `"just a string"
---
- a
- list
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: real
---
`)
	resources, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || resources[0].Name != "real" {
		t.Errorf("resources = %+v", resources)
	}
	if resources[0].DocIndex != 2 {
		t.Errorf("DocIndex = %d, want 2 (original document position)", resources[0].DocIndex)
	}
}

func TestParseDirRecursiveAndExtensions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", "apiVersion: v1\nkind: A\nmetadata:\n  name: a\n")
	writeFile(t, dir, "sub/b.yml", "apiVersion: v1\nkind: B\nmetadata:\n  name: b\n")
	writeFile(t, dir, "sub/c.txt", "not yaml")
	writeFile(t, dir, ".hidden/d.yaml", "apiVersion: v1\nkind: D\nmetadata:\n  name: d\n")

	res, err := ParsePaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, r := range res.Resources {
		kinds = append(kinds, r.Kind)
	}
	if len(res.Resources) != 2 {
		t.Fatalf("got kinds %v, want [A B]", kinds)
	}
	if res.FilesScanned != 2 {
		t.Errorf("FilesScanned = %d, want 2", res.FilesScanned)
	}
}

func TestParsePathsMissingPath(t *testing.T) {
	_, err := ParsePaths([]string{"/nonexistent/path/xyz"})
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestParseSingleFilePath(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "one.yaml", "apiVersion: v1\nkind: One\nmetadata:\n  name: one\n")
	res, err := ParsePaths([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resources) != 1 || res.Resources[0].Kind != "One" {
		t.Errorf("resources = %+v", res.Resources)
	}
}

func TestParseFileTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.yaml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected error for oversized file")
	}
}

func TestParseDeterministicOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "z.yaml", "apiVersion: v1\nkind: Z\nmetadata:\n  name: z\n")
	writeFile(t, dir, "a.yaml", "apiVersion: v1\nkind: A\nmetadata:\n  name: a\n")
	res, err := ParsePaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Resources[0].Kind != "A" || res.Resources[1].Kind != "Z" {
		t.Errorf("resources not sorted by path: %+v", res.Resources)
	}
}

func TestStringMapCoercions(t *testing.T) {
	got := stringMap(map[string]interface{}{
		"s": "v", "b": true, "i": 3, "f": 2.0, "skip": []interface{}{},
	})
	want := map[string]string{"s": "v", "b": "true", "i": "3", "f": "2"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("stringMap[%s] = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["skip"]; ok {
		t.Error("non-scalar values should be skipped")
	}
	if stringMap("not a map") != nil {
		t.Error("non-map input should return nil")
	}
}

func TestAPIGroupCoreResource(t *testing.T) {
	r := Resource{APIVersion: "v1"}
	if g := r.APIGroup(); g != "" {
		t.Errorf("core resource group = %q, want empty", g)
	}
}
