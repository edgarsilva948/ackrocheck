package ack

import (
	"testing"
)

func TestIsACKGroup(t *testing.T) {
	tests := []struct {
		group string
		want  bool
	}{
		{"rds.services.k8s.aws", true},
		{"s3.services.k8s.aws", true},
		{"kro.run", false},
		{"apps", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsACKGroup(tt.group); got != tt.want {
			t.Errorf("IsACKGroup(%q) = %v, want %v", tt.group, got, tt.want)
		}
	}
}

func TestServiceFromGroup(t *testing.T) {
	if got := ServiceFromGroup("rds.services.k8s.aws"); got != "rds" {
		t.Errorf("got %q, want rds", got)
	}
	if got := ServiceFromGroup("apps"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestParsePolicyDocumentJSONString(t *testing.T) {
	doc, ok := ParsePolicyDocument(`{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "allow", "Action": "*", "Resource": "*"}
		]
	}`)
	if !ok {
		t.Fatal("expected document to parse")
	}
	stmts := doc["Statement"].([]interface{})
	if len(stmts) != 1 {
		t.Fatalf("got %d statements", len(stmts))
	}
	stmt := stmts[0].(map[string]interface{})
	if stmt["Effect"] != "Allow" {
		t.Errorf("Effect = %v, want canonical Allow", stmt["Effect"])
	}
	actions := stmt["Action"].([]interface{})
	if len(actions) != 1 || actions[0] != "*" {
		t.Errorf("Action = %v, want [*]", actions)
	}
	if stmt["HasCondition"] != false {
		t.Errorf("HasCondition = %v, want false", stmt["HasCondition"])
	}
}

func TestParsePolicyDocumentSingleStatementObject(t *testing.T) {
	doc, ok := ParsePolicyDocument(map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": map[string]interface{}{
			"Effect": "Allow", "Action": []interface{}{"s3:GetObject"}, "Resource": "arn:x",
			"Condition": map[string]interface{}{"StringEquals": map[string]interface{}{"a": "b"}},
		},
	})
	if !ok {
		t.Fatal("expected document to parse")
	}
	stmts := doc["Statement"].([]interface{})
	if len(stmts) != 1 {
		t.Fatalf("single statement object should be wrapped, got %d", len(stmts))
	}
	stmt := stmts[0].(map[string]interface{})
	res := stmt["Resource"].([]interface{})
	if len(res) != 1 || res[0] != "arn:x" {
		t.Errorf("Resource = %v", res)
	}
	if stmt["HasCondition"] != true {
		t.Errorf("HasCondition = %v, want true", stmt["HasCondition"])
	}
}

func TestParsePolicyDocumentPrincipalCanonicalization(t *testing.T) {
	tests := []struct {
		name      string
		principal interface{}
	}{
		{"string star", "*"},
		{"map star string", map[string]interface{}{"AWS": "*"}},
		{"map star list", map[string]interface{}{"AWS": []interface{}{"*"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, ok := ParsePolicyDocument(map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{"Effect": "Allow", "Principal": tt.principal, "Action": "sts:AssumeRole"},
				},
			})
			if !ok {
				t.Fatal("expected document to parse")
			}
			stmt := doc["Statement"].([]interface{})[0].(map[string]interface{})
			principal := stmt["Principal"].(map[string]interface{})
			aws := principal["AWS"].([]interface{})
			if len(aws) != 1 || aws[0] != "*" {
				t.Errorf("Principal.AWS = %v, want [*]", aws)
			}
		})
	}
}

func TestParsePolicyDocumentRejectsGarbage(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
	}{
		{"not json", "this is not json"},
		{"json array", `["a"]`},
		{"invalid json object", `{"unclosed": `},
		{"no statement key", map[string]interface{}{"Version": "2012-10-17"}},
		{"statement wrong type", map[string]interface{}{"Statement": "oops"}},
		{"integer", 42},
		{"nil", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := ParsePolicyDocument(tt.in); ok {
				t.Error("expected parse to fail")
			}
		})
	}
}

func TestParsePolicyDocumentLowercaseKeys(t *testing.T) {
	doc, ok := ParsePolicyDocument(map[string]interface{}{
		"statement": []interface{}{
			map[string]interface{}{"effect": "allow", "action": "*", "resource": "*"},
		},
	})
	if !ok {
		t.Fatal("expected document to parse")
	}
	stmt := doc["Statement"].([]interface{})[0].(map[string]interface{})
	if stmt["Effect"] != "Allow" {
		t.Errorf("Effect = %v", stmt["Effect"])
	}
	if actions := stmt["Action"].([]interface{}); actions[0] != "*" {
		t.Errorf("Action = %v", actions)
	}
}

func TestNormalizePolicyDocuments(t *testing.T) {
	raw := map[string]interface{}{
		"apiVersion": "iam.services.k8s.aws/v1alpha1",
		"kind":       "Policy",
		"spec": map[string]interface{}{
			"policyDocument": `{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}`,
			"name":           "x",
		},
	}
	out := NormalizePolicyDocuments(raw)
	if _, ok := raw[NormalizedKeyPrefix]; ok {
		t.Error("input map must not be mutated")
	}
	meta, ok := out[NormalizedKeyPrefix].(map[string]interface{})
	if !ok {
		t.Fatal("normalized key missing")
	}
	docs := meta["policyDocuments"].(map[string]interface{})
	if _, ok := docs["policyDocument"]; !ok {
		t.Error("policyDocument not normalized")
	}
}

func TestNormalizePolicyDocumentsNoOp(t *testing.T) {
	raw := map[string]interface{}{
		"spec": map[string]interface{}{"name": "x"},
	}
	out := NormalizePolicyDocuments(raw)
	if _, ok := out[NormalizedKeyPrefix]; ok {
		t.Error("should not inject key when no documents found")
	}
	noSpec := map[string]interface{}{"kind": "X"}
	if out := NormalizePolicyDocuments(noSpec); len(out) != 1 {
		t.Error("no spec should be returned unchanged")
	}
}

func TestNormalizePolicyDocumentsUnparseableIgnored(t *testing.T) {
	raw := map[string]interface{}{
		"spec": map[string]interface{}{
			"policy": "not a json document",
		},
	}
	out := NormalizePolicyDocuments(raw)
	if _, ok := out[NormalizedKeyPrefix]; ok {
		t.Error("unparseable documents should be ignored")
	}
}
