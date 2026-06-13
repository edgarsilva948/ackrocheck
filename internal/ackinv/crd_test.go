package ackinv

import (
	"testing"
)

const sampleCRD = `
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: buckets.s3.services.k8s.aws
spec:
  group: s3.services.k8s.aws
  names:
    kind: Bucket
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          spec:
            properties:
              name:
                type: string
              acl:
                type: string
              publicAccessBlock:
                type: object
                properties:
                  blockPublicACLs:
                    type: boolean
                  restrictPublicBuckets:
                    type: boolean
              encryption:
                type: object
                properties:
                  rules:
                    type: array
                    items:
                      type: object
                      properties:
                        applyServerSideEncryptionByDefault:
                          type: object
                          properties:
                            sseAlgorithm:
                              type: string
              tagging:
                type: object
                properties:
                  tagSet:
                    type: array
                    items:
                      type: object
                      properties:
                        key:
                          type: string
                        value:
                          type: string
              freeform:
                type: object
                x-kubernetes-preserve-unknown-fields: true
              labels:
                type: object
                additionalProperties:
                  type: string
            type: object
        type: object
`

func parseSample(t *testing.T) *Kind {
	t.Helper()
	k, err := ParseCRD([]byte(sampleCRD))
	if err != nil {
		t.Fatalf("ParseCRD: %v", err)
	}
	return k
}

func TestParseCRDBasics(t *testing.T) {
	k := parseSample(t)
	if k.Kind != "Bucket" || k.Group != "s3.services.k8s.aws" {
		t.Fatalf("unexpected kind/group: %q %q", k.Kind, k.Group)
	}
	if len(k.Versions) != 1 || k.Versions[0] != "v1alpha1" {
		t.Fatalf("unexpected versions: %v", k.Versions)
	}
}

func TestFlattenedFieldPaths(t *testing.T) {
	k := parseSample(t)
	want := map[string]string{
		"spec.acl":                               "string",
		"spec.publicAccessBlock.blockPublicACLs": "boolean",
		"spec.encryption.rules[].applyServerSideEncryptionByDefault.sseAlgorithm": "string",
		"spec.tagging.tagSet[].key": "string",
		"spec.freeform":             "opaque",
		"spec.labels":               "map",
	}
	got := map[string]string{}
	for _, f := range k.Fields {
		got[f.Path] = f.Type
	}
	for path, typ := range want {
		if got[path] != typ {
			t.Errorf("field %s: got type %q, want %q (all: %v)", path, got[path], typ, got)
		}
	}
}

func TestHasPath(t *testing.T) {
	k := parseSample(t)
	valid := []string{
		"spec.acl",
		"spec.publicAccessBlock.blockPublicACLs",
		// Path addressing the list itself (used by any/all operators).
		"spec.encryption.rules",
		// Full path through a list, as flattened minus markers.
		"spec.encryption.rules.applyServerSideEncryptionByDefault.sseAlgorithm",
		// Prefix of a deeper field at a segment boundary.
		"spec.publicAccessBlock",
		// Descent below an opaque/map field cannot be validated -> accepted.
		"spec.freeform.anything.goes",
		"spec.labels.env",
		// Synthetic injected document and self-reference.
		"__ackrocheck.policyDocuments.policy.Statement",
		".",
	}
	for _, p := range valid {
		if !k.HasPath(p) {
			t.Errorf("HasPath(%q) = false, want true", p)
		}
	}
	invalid := []string{
		"spec.nonexistent",
		"spec.publicAccessBlock.blockEverything",
		"spec.aclx", // not a segment boundary
		"spec.encryption.rules.applyServerSideEncryptionByDefault.kmsKeyID",
	}
	for _, p := range invalid {
		if k.HasPath(p) {
			t.Errorf("HasPath(%q) = true, want false", p)
		}
	}
}
