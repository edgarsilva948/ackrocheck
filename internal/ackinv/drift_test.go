package ackinv

import (
	"strings"
	"testing"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

func driftFixtures() (*Inventory, *Inventory, []policy.Policy) {
	old := &Inventory{Services: []Service{
		{Name: "s3", Release: "v1.5.0", Kinds: []Kind{{
			Kind: "Bucket", Group: "s3.services.k8s.aws",
			Fields: []Field{
				{Path: "spec.acl", Type: "string"},
				{Path: "spec.legacyField", Type: "string"},
			},
		}}},
		{Name: "gone", Release: "v0.1.0", Kinds: []Kind{}},
	}}
	updated := &Inventory{Services: []Service{
		{Name: "s3", Release: "v1.6.0", Kinds: []Kind{
			{
				Kind: "Bucket", Group: "s3.services.k8s.aws",
				Fields: []Field{
					{Path: "spec.acl", Type: "string"},
					{Path: "spec.objectLockEnabled", Type: "boolean"},
				},
			},
			{Kind: "AccessPoint", Group: "s3.services.k8s.aws"},
		}},
		{Name: "fresh", Release: "v0.0.1", Kinds: []Kind{}},
	}}
	policies := []policy.Policy{{
		ID: "ACKRO_TEST_S3",
		Match: policy.Match{
			APIGroups: []string{"s3.services.k8s.aws"},
			Kinds:     []string{"Bucket"},
		},
		Assertions: []policy.Assertion{
			// References the field removed in the new inventory.
			{Path: "spec.legacyField", Operator: policy.OpExists},
		},
	}}
	return old, updated, policies
}

func TestClassifyDrift(t *testing.T) {
	old, updated, policies := driftFixtures()
	d := Classify(old, updated, policies)

	if len(d.BrokenPolicies) != 1 || !strings.Contains(d.BrokenPolicies[0], "spec.legacyField") {
		t.Errorf("broken policies: %v", d.BrokenPolicies)
	}
	if len(d.NewServices) != 1 || d.NewServices[0] != "fresh" {
		t.Errorf("new services: %v", d.NewServices)
	}
	if len(d.RemovedServices) != 1 || d.RemovedServices[0] != "gone" {
		t.Errorf("removed services: %v", d.RemovedServices)
	}
	if len(d.NewKinds) != 1 || d.NewKinds[0] != "s3: AccessPoint" {
		t.Errorf("new kinds: %v", d.NewKinds)
	}
	if len(d.NewFields) != 1 || d.NewFields[0] != "s3 Bucket: spec.objectLockEnabled" {
		t.Errorf("new fields: %v", d.NewFields)
	}
	if len(d.RemovedFields) != 1 || d.RemovedFields[0] != "s3 Bucket: spec.legacyField" {
		t.Errorf("removed fields: %v", d.RemovedFields)
	}
	if len(d.ReleaseBumps) != 1 || d.ReleaseBumps[0] != "s3: v1.5.0 -> v1.6.0" {
		t.Errorf("release bumps: %v", d.ReleaseBumps)
	}
	if d.Empty() {
		t.Error("Empty() = true with drift present")
	}
}

func TestDriftIssuesAndReport(t *testing.T) {
	old, updated, policies := driftFixtures()
	d := Classify(old, updated, policies)

	issues := d.Issues()
	labels := map[string]bool{}
	for _, is := range issues {
		for _, l := range is.Labels {
			labels[l] = true
		}
	}
	for _, want := range []string{"broken-policy", "new-service", "schema-drift"} {
		if !labels[want] {
			t.Errorf("missing issue label %q (issues: %+v)", want, issues)
		}
	}

	report := d.Report()
	for _, want := range []string{"Broken policies", "spec.legacyField", "fresh", "v1.5.0 -> v1.6.0"} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestNoDrift(t *testing.T) {
	old, _, _ := driftFixtures()
	d := Classify(old, old, nil)
	if !d.Empty() {
		t.Errorf("expected empty drift, got %+v", d)
	}
	if len(d.Issues()) != 0 {
		t.Errorf("expected no issues, got %v", d.Issues())
	}
}

func TestFieldDriftIgnoredOnUncoveredKinds(t *testing.T) {
	old, updated, _ := driftFixtures()
	// Without any policies covering Bucket, field-level drift is suppressed
	// (it belongs to the coverage backlog, not the drift report).
	d := Classify(old, updated, nil)
	if len(d.NewFields) != 0 || len(d.RemovedFields) != 0 {
		t.Errorf("field drift on uncovered kind should be ignored: %+v", d)
	}
	// Kind-level drift still reported.
	if len(d.NewKinds) != 1 {
		t.Errorf("new kinds: %v", d.NewKinds)
	}
}
