package scanner

import (
	"path/filepath"
	"testing"

	"github.com/edgarsilva948/ackrocheck/controls"
	"github.com/edgarsilva948/ackrocheck/internal/parser"
	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

func testdata(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...)
}

func scanPath(t *testing.T, opts Options, paths ...string) *Report {
	t.Helper()
	builtin, err := controls.Builtin()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	parsed, err := parser.ParsePaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	return New(builtin, opts).Scan(parsed)
}

func findingIDs(r *Report) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range r.Findings {
		out[f.ControlID+"/"+f.ResourceName] = f
	}
	return out
}

func TestBuiltinControlsLoad(t *testing.T) {
	policies, err := controls.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) < 20 {
		t.Errorf("expected at least 20 built-in controls, got %d", len(policies))
	}
	ids := map[string]bool{}
	for _, p := range policies {
		ids[p.ID] = true
	}
	for _, want := range []string{
		"ACKRO_AWS_RDS_001", "ACKRO_AWS_RDS_002", "ACKRO_AWS_RDS_003", "ACKRO_AWS_RDS_004",
		"ACKRO_AWS_S3_001", "ACKRO_AWS_S3_002", "ACKRO_AWS_S3_003", "ACKRO_AWS_S3_004",
		"ACKRO_AWS_S3_005", "ACKRO_AWS_S3_006",
		"ACKRO_AWS_IAM_001", "ACKRO_AWS_IAM_002", "ACKRO_AWS_IAM_003", "ACKRO_AWS_IAM_004",
		"ACKRO_AWS_SQS_001", "ACKRO_AWS_SQS_002",
		"ACKRO_AWS_SNS_001", "ACKRO_AWS_SNS_002",
		"ACKRO_AWS_ECR_001", "ACKRO_AWS_ECR_002",
		"ACKRO_AWS_EC2_001", "ACKRO_AWS_EC2_002", "ACKRO_AWS_EC2_003", "ACKRO_AWS_EC2_004", "ACKRO_AWS_EC2_005",
		"ACKRO_AWS_EKS_001", "ACKRO_AWS_EKS_002", "ACKRO_AWS_EKS_003",
		"ACKRO_AWS_ECS_001", "ACKRO_AWS_ECS_002",
		"ACKRO_AWS_ELASTICACHE_001", "ACKRO_AWS_ELASTICACHE_002",
		"ACKRO_AWS_EFS_001",
		"ACKRO_AWS_ELBV2_001",
		"ACKRO_AWS_CLOUDFRONT_001", "ACKRO_AWS_CLOUDFRONT_002",
		"ACKRO_AWS_MSK_001", "ACKRO_AWS_MSK_002",
		"ACKRO_AWS_DOCUMENTDB_001", "ACKRO_AWS_DOCUMENTDB_002",
		"ACKRO_AWS_OPENSEARCH_001", "ACKRO_AWS_OPENSEARCH_002", "ACKRO_AWS_OPENSEARCH_003",
		"ACKRO_AWS_CLOUDTRAIL_001", "ACKRO_AWS_CLOUDTRAIL_002",
	} {
		if !ids[want] {
			t.Errorf("missing built-in control %s", want)
		}
	}
}

func TestPassFixturesProduceNoFindings(t *testing.T) {
	report := scanPath(t, Options{}, testdata("pass"))
	if len(report.Findings) != 0 {
		for _, f := range report.Findings {
			t.Errorf("unexpected finding: %s on %s (%s)", f.ControlID, f.ResourceName, f.Message)
		}
	}
	if report.Summary.ResourcesScanned == 0 {
		t.Error("no resources scanned")
	}
}

func TestFailFixtures(t *testing.T) {
	report := scanPath(t, Options{}, testdata("fail"))
	got := findingIDs(report)
	wantFailed := []string{
		// RDS
		"ACKRO_AWS_RDS_001/insecure-db",
		"ACKRO_AWS_RDS_002/insecure-db",
		"ACKRO_AWS_RDS_003/insecure-db",
		"ACKRO_AWS_RDS_004/insecure-db",
		// S3
		"ACKRO_AWS_S3_001/insecure-bucket",
		"ACKRO_AWS_S3_002/insecure-bucket",
		"ACKRO_AWS_S3_003/insecure-bucket",
		"ACKRO_AWS_S3_004/insecure-bucket",
		"ACKRO_AWS_S3_005/insecure-bucket",
		"ACKRO_AWS_S3_006/insecure-bucket",
		// IAM
		"ACKRO_AWS_IAM_001/admin-policy",
		"ACKRO_AWS_IAM_002/admin-policy",
		"ACKRO_AWS_IAM_004/admin-policy",
		"ACKRO_AWS_IAM_003/open-role",
		"ACKRO_AWS_IAM_004/passrole-policy",
		// Messaging
		"ACKRO_AWS_SQS_001/open-queue",
		"ACKRO_AWS_SQS_002/open-queue",
		"ACKRO_AWS_SNS_001/open-topic",
		"ACKRO_AWS_SNS_002/open-topic",
		"ACKRO_AWS_ECR_001/open-repo",
		"ACKRO_AWS_ECR_002/open-repo",
		// EC2
		"ACKRO_AWS_EC2_001/open-sg",
		"ACKRO_AWS_EC2_002/open-sg",
		"ACKRO_AWS_EC2_003/open-sg",
		"ACKRO_AWS_EC2_004/open-sg",
		// Compute (EKS/ECS)
		"ACKRO_AWS_EKS_001/insecure-eks",
		"ACKRO_AWS_EKS_002/insecure-eks",
		"ACKRO_AWS_EKS_003/insecure-eks",
		"ACKRO_AWS_ECS_001/insecure-ecs-svc",
		"ACKRO_AWS_ECS_002/insecure-taskdef",
		// Data stores (ElastiCache/EFS/DocumentDB/OpenSearch)
		"ACKRO_AWS_ELASTICACHE_001/insecure-cache",
		"ACKRO_AWS_ELASTICACHE_002/insecure-cache",
		"ACKRO_AWS_EFS_001/insecure-fs",
		"ACKRO_AWS_DOCUMENTDB_001/insecure-docdb",
		"ACKRO_AWS_DOCUMENTDB_002/insecure-docdb",
		"ACKRO_AWS_OPENSEARCH_001/insecure-domain",
		"ACKRO_AWS_OPENSEARCH_002/insecure-domain",
		"ACKRO_AWS_OPENSEARCH_003/insecure-domain",
		// Edge/streaming/audit (ELBv2/CloudFront/MSK/CloudTrail)
		"ACKRO_AWS_ELBV2_001/insecure-listener",
		"ACKRO_AWS_CLOUDFRONT_001/insecure-dist",
		"ACKRO_AWS_CLOUDFRONT_002/insecure-dist",
		"ACKRO_AWS_MSK_001/insecure-msk",
		"ACKRO_AWS_MSK_002/insecure-msk",
		"ACKRO_AWS_CLOUDTRAIL_001/insecure-trail",
		"ACKRO_AWS_CLOUDTRAIL_002/insecure-trail",
	}
	for _, key := range wantFailed {
		f, ok := got[key]
		if !ok {
			t.Errorf("missing expected finding %s", key)
			continue
		}
		if f.Status != StatusFailed {
			t.Errorf("%s status = %s, want FAILED", key, f.Status)
		}
	}
	// passrole-policy must NOT trip the broad wildcard-action control.
	if _, ok := got["ACKRO_AWS_IAM_001/passrole-policy"]; ok {
		t.Error("passrole-policy should not fail ACKRO_AWS_IAM_001")
	}
	// IPv6 RDP control must not fire: fixture only opens ::/0 on port 22.
	if _, ok := got["ACKRO_AWS_EC2_005/open-sg"]; ok {
		t.Error("open-sg should not fail ACKRO_AWS_EC2_005 (no ::/0 on 3389)")
	}
}

func TestFindingFieldsPopulated(t *testing.T) {
	report := scanPath(t, Options{}, testdata("fail", "rds_insecure.yaml"))
	if len(report.Findings) == 0 {
		t.Fatal("expected findings")
	}
	f := report.Findings[0]
	if f.ControlID == "" || f.Title == "" || f.Severity == "" || f.Message == "" {
		t.Errorf("incomplete finding: %+v", f)
	}
	if f.ResourceAPIVersion != "rds.services.k8s.aws/v1alpha1" || f.ResourceKind != "DBInstance" {
		t.Errorf("resource identity: %+v", f)
	}
	if f.ResourceName != "insecure-db" || f.ResourceNamespace != "apps" {
		t.Errorf("resource name/ns: %+v", f)
	}
	if f.FilePath == "" || f.Line == 0 {
		t.Errorf("file context: %+v", f)
	}
	if f.Remediation == "" {
		t.Errorf("remediation missing: %+v", f)
	}
}

func TestProductionOnlyControl(t *testing.T) {
	builtin, err := controls.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		labels   map[string]string
		annots   map[string]string
		expected bool
	}{
		{"environment prod label", map[string]string{"environment": "prod"}, nil, true},
		{"environment production label", map[string]string{"environment": "production"}, nil, true},
		{"env production label", map[string]string{"env": "production"}, nil, true},
		{"env prod label", map[string]string{"env": "prod"}, nil, true},
		{"annotation production", nil, map[string]string{"ackrocheck.dev/environment": "production"}, true},
		{"staging label", map[string]string{"environment": "staging"}, nil, false},
		{"no labels", nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := parser.Resource{
				APIVersion:  "rds.services.k8s.aws/v1alpha1",
				Kind:        "DBInstance",
				Name:        "db",
				Labels:      tc.labels,
				Annotations: tc.annots,
				Spec:        map[string]interface{}{"storageEncrypted": true, "backupRetentionPeriod": 7},
				Raw: map[string]interface{}{
					"spec": map[string]interface{}{"storageEncrypted": true, "backupRetentionPeriod": 7},
				},
				FilePath: "x.yaml",
			}
			report := New(builtin, Options{}).Scan(&parser.Result{Resources: []parser.Resource{res}, FilesScanned: 1})
			hasDeletionFinding := false
			for _, f := range report.Findings {
				if f.ControlID == "ACKRO_AWS_RDS_004" {
					hasDeletionFinding = true
				}
			}
			if hasDeletionFinding != tc.expected {
				t.Errorf("deletion protection finding = %v, want %v", hasDeletionFinding, tc.expected)
			}
		})
	}
}

func TestKROInsecureRGD(t *testing.T) {
	report := scanPath(t, Options{}, testdata("kro", "rgd_insecure.yaml"))
	if len(report.Findings) == 0 {
		t.Fatal("expected findings for insecure RGD")
	}
	for _, f := range report.Findings {
		if f.ParentResourceKind != "ResourceGraphDefinition" || f.ParentResourceName != "insecure-db-stack" {
			t.Errorf("missing KRO parent context: %+v", f)
		}
		if f.EmbeddedResourceKind != "DBInstance" || f.EmbeddedResourceName != "stack-db" {
			t.Errorf("missing embedded context: %+v", f)
		}
	}
	got := findingIDs(report)
	for _, key := range []string{
		"ACKRO_AWS_RDS_001/stack-db",
		"ACKRO_AWS_RDS_002/stack-db",
		"ACKRO_AWS_RDS_003/stack-db",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing expected KRO finding %s", key)
		}
	}
}

func TestKROSecureRGD(t *testing.T) {
	report := scanPath(t, Options{}, testdata("kro", "rgd_secure.yaml"))
	if len(report.Findings) != 0 {
		for _, f := range report.Findings {
			t.Errorf("unexpected finding: %s (%s)", f.ControlID, f.Message)
		}
	}
	if report.Summary.ResourcesScanned != 1 {
		t.Errorf("ResourcesScanned = %d, want 1 (the RGD)", report.Summary.ResourcesScanned)
	}
}

func TestKRODynamicFieldsWarn(t *testing.T) {
	report := scanPath(t, Options{}, testdata("kro", "rgd_dynamic.yaml"))
	var warning *Finding
	for i := range report.Findings {
		if report.Findings[i].ControlID == "ACKRO_AWS_RDS_001" {
			warning = &report.Findings[i]
		}
	}
	if warning == nil {
		t.Fatal("expected a finding for templated storageEncrypted")
	}
	if warning.Status != StatusWarning {
		t.Errorf("status = %s, want WARNING", warning.Status)
	}
	if warning.ParentResourceName != "dynamic-db-stack" {
		t.Errorf("parent context: %+v", warning)
	}
}

func TestFrameworkFilter(t *testing.T) {
	// Only KRO: ACK plain resources skipped.
	report := scanPath(t, Options{Frameworks: []Framework{FrameworkKRO}},
		testdata("fail", "rds_insecure.yaml"), testdata("kro", "rgd_insecure.yaml"))
	for _, f := range report.Findings {
		if f.ParentResourceKind == "" {
			t.Errorf("plain ACK finding with framework=kro: %+v", f)
		}
	}
	// Only ACK: RGD skipped.
	report = scanPath(t, Options{Frameworks: []Framework{FrameworkACK}},
		testdata("fail", "rds_insecure.yaml"), testdata("kro", "rgd_insecure.yaml"))
	for _, f := range report.Findings {
		if f.ParentResourceKind != "" {
			t.Errorf("KRO finding with framework=ack: %+v", f)
		}
	}
	if len(report.Findings) == 0 {
		t.Error("expected ACK findings")
	}
}

func TestSeverityFilter(t *testing.T) {
	report := scanPath(t, Options{MinSeverity: policy.SeverityHigh}, testdata("fail", "rds_insecure.yaml"))
	for _, f := range report.Findings {
		if !f.Severity.AtLeast(policy.SeverityHigh) {
			t.Errorf("finding below min severity: %+v", f)
		}
	}
	// MEDIUM findings (backup retention, deletion protection) filtered out.
	if len(report.Findings) != 2 {
		t.Errorf("got %d findings, want 2", len(report.Findings))
	}
}

func TestSummaryCounts(t *testing.T) {
	report := scanPath(t, Options{}, testdata("fail", "rds_insecure.yaml"))
	s := report.Summary
	if s.Findings != len(report.Findings) {
		t.Errorf("summary findings %d != %d", s.Findings, len(report.Findings))
	}
	if s.High != 2 || s.Medium != 2 {
		t.Errorf("high=%d medium=%d, want 2/2", s.High, s.Medium)
	}
	if s.FilesScanned != 1 || s.ResourcesScanned != 1 {
		t.Errorf("files=%d resources=%d", s.FilesScanned, s.ResourcesScanned)
	}
}

func TestParseErrorsInReport(t *testing.T) {
	report := scanPath(t, Options{}, testdata("malformed"))
	if len(report.ParseErrors) != 1 || report.Summary.ParseErrors != 1 {
		t.Errorf("parse errors = %+v", report.ParseErrors)
	}
}

func TestSortFindingsDeterministic(t *testing.T) {
	fs := []Finding{
		{ControlID: "B", Severity: policy.SeverityLow, FilePath: "a.yaml", ResourceName: "x"},
		{ControlID: "A", Severity: policy.SeverityCritical, FilePath: "b.yaml", ResourceName: "y"},
		{ControlID: "A", Severity: policy.SeverityLow, FilePath: "a.yaml", ResourceName: "x"},
		{ControlID: "A", Severity: policy.SeverityLow, FilePath: "a.yaml", ResourceName: "w"},
	}
	SortFindings(fs)
	if fs[0].Severity != policy.SeverityCritical {
		t.Error("critical should sort first")
	}
	if fs[1].ResourceName != "w" {
		t.Errorf("resource name tiebreak failed: %+v", fs[1])
	}
	if fs[2].ControlID != "A" || fs[3].ControlID != "B" {
		t.Errorf("control id tiebreak failed: %v %v", fs[2].ControlID, fs[3].ControlID)
	}
}
