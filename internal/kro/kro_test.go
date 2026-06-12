package kro

import (
	"testing"

	"github.com/edgarsilva948/ackrocheck/internal/parser"
)

func rgdResource(spec map[string]interface{}) *parser.Resource {
	return &parser.Resource{
		APIVersion: "kro.run/v1alpha1",
		Kind:       KindResourceGraphDefinition,
		Name:       "my-rgd",
		Spec:       spec,
		FilePath:   "rgd.yaml",
		DocIndex:   0,
		Line:       3,
	}
}

func TestIsResourceGraphDefinition(t *testing.T) {
	if !IsResourceGraphDefinition(rgdResource(nil)) {
		t.Error("expected RGD to be detected")
	}
	notRGD := &parser.Resource{APIVersion: "kro.run/v1alpha1", Kind: "Other"}
	if IsResourceGraphDefinition(notRGD) {
		t.Error("non-RGD kind detected as RGD")
	}
	wrongGroup := &parser.Resource{APIVersion: "apps/v1", Kind: KindResourceGraphDefinition}
	if IsResourceGraphDefinition(wrongGroup) {
		t.Error("wrong group detected as RGD")
	}
}

func TestExtractEmbedded(t *testing.T) {
	rgd := rgdResource(map[string]interface{}{
		"resources": []interface{}{
			map[string]interface{}{
				"id": "db",
				"template": map[string]interface{}{
					"apiVersion": "rds.services.k8s.aws/v1alpha1",
					"kind":       "DBInstance",
					"metadata": map[string]interface{}{
						"name":   "stack-db",
						"labels": map[string]interface{}{"env": "prod"},
					},
					"spec": map[string]interface{}{"storageEncrypted": false},
				},
			},
			// Legacy "manifest" key.
			map[string]interface{}{
				"id": "bucket",
				"manifest": map[string]interface{}{
					"apiVersion": "s3.services.k8s.aws/v1alpha1",
					"kind":       "Bucket",
					"metadata":   map[string]interface{}{"name": "stack-bucket"},
				},
			},
			// No template: skipped.
			map[string]interface{}{"id": "empty"},
			// Template without kind: skipped.
			map[string]interface{}{
				"id":       "incomplete",
				"template": map[string]interface{}{"apiVersion": "v1"},
			},
			// Non-map entry: skipped.
			"garbage",
		},
	})

	embedded := ExtractEmbedded(rgd)
	if len(embedded) != 2 {
		t.Fatalf("got %d embedded resources, want 2", len(embedded))
	}
	db := embedded[0]
	if db.ID != "db" || db.Resource.Kind != "DBInstance" || db.Resource.Name != "stack-db" {
		t.Errorf("unexpected first embedded: %+v", db)
	}
	if db.Resource.Labels["env"] != "prod" {
		t.Errorf("labels not extracted: %v", db.Resource.Labels)
	}
	if db.Resource.FilePath != "rgd.yaml" || db.Resource.Line != 3 {
		t.Errorf("file context not inherited: %+v", db.Resource)
	}
	if v, ok := db.Resource.Spec["storageEncrypted"]; !ok || v != false {
		t.Errorf("spec not extracted: %v", db.Resource.Spec)
	}
	if embedded[1].ID != "bucket" || embedded[1].Resource.Kind != "Bucket" {
		t.Errorf("unexpected second embedded: %+v", embedded[1])
	}
}

func TestExtractEmbeddedDefaultID(t *testing.T) {
	rgd := rgdResource(map[string]interface{}{
		"resources": []interface{}{
			map[string]interface{}{
				"template": map[string]interface{}{
					"apiVersion": "v1", "kind": "ConfigMap",
				},
			},
		},
	})
	embedded := ExtractEmbedded(rgd)
	if len(embedded) != 1 || embedded[0].ID != "resource-0" {
		t.Errorf("embedded = %+v", embedded)
	}
}

func TestExtractEmbeddedNoResources(t *testing.T) {
	if got := ExtractEmbedded(rgdResource(nil)); got != nil {
		t.Errorf("nil spec: got %v", got)
	}
	if got := ExtractEmbedded(rgdResource(map[string]interface{}{"resources": "wrong"})); got != nil {
		t.Errorf("non-list resources: got %v", got)
	}
}
