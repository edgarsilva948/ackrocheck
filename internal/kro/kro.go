// Package kro provides best-effort static analysis of KRO
// ResourceGraphDefinition manifests. It extracts embedded resource templates
// so they can be evaluated by the regular policy engine.
//
// Limitations: KRO templates may contain CEL expressions like
// "${schema.spec.encrypted}". AckroCheck does not evaluate CEL. Fields whose
// values are templated are reported as warnings ("user-controlled, cannot be
// statically verified") rather than pass/fail results.
package kro

import (
	"fmt"

	"github.com/edgarsilva948/ackrocheck/internal/parser"
)

// APIGroup is the KRO API group.
const APIGroup = "kro.run"

// KindResourceGraphDefinition is the RGD kind.
const KindResourceGraphDefinition = "ResourceGraphDefinition"

// IsResourceGraphDefinition reports whether a resource is a KRO RGD.
func IsResourceGraphDefinition(r *parser.Resource) bool {
	return r.APIGroup() == APIGroup && r.Kind == KindResourceGraphDefinition
}

// Embedded is a resource template found inside an RGD.
type Embedded struct {
	// ID is the RGD-local identifier of the resource (spec.resources[].id).
	ID string
	// Resource is the embedded template parsed as a regular resource. Its
	// FilePath and DocIndex point at the parent RGD document.
	Resource parser.Resource
}

// ExtractEmbedded returns all embedded resource templates of an RGD that look
// like Kubernetes resources (have apiVersion and kind). Templates appear
// under spec.resources[].template; the legacy key "manifest" is also
// accepted. Entries that are not maps or lack apiVersion/kind are skipped.
func ExtractEmbedded(rgd *parser.Resource) []Embedded {
	if rgd.Spec == nil {
		return nil
	}
	list, ok := rgd.Spec["resources"].([]interface{})
	if !ok {
		return nil
	}
	var out []Embedded
	for i, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := entry["id"].(string)
		if id == "" {
			id = fmt.Sprintf("resource-%d", i)
		}
		tmpl, ok := entry["template"].(map[string]interface{})
		if !ok {
			tmpl, ok = entry["manifest"].(map[string]interface{})
		}
		if !ok {
			continue
		}
		res := buildEmbedded(tmpl, rgd)
		if res.APIVersion == "" || res.Kind == "" {
			continue
		}
		out = append(out, Embedded{ID: id, Resource: res})
	}
	return out
}

func buildEmbedded(tmpl map[string]interface{}, parent *parser.Resource) parser.Resource {
	r := parser.Resource{
		Raw:      tmpl,
		FilePath: parent.FilePath,
		DocIndex: parent.DocIndex,
		Line:     parent.Line,
	}
	r.APIVersion, _ = tmpl["apiVersion"].(string)
	r.Kind, _ = tmpl["kind"].(string)
	if meta, ok := tmpl["metadata"].(map[string]interface{}); ok {
		r.Name, _ = meta["name"].(string)
		r.Namespace, _ = meta["namespace"].(string)
		r.Labels = stringMap(meta["labels"])
		r.Annotations = stringMap(meta["annotations"])
	}
	if spec, ok := tmpl["spec"].(map[string]interface{}); ok {
		r.Spec = spec
	}
	return r
}

func stringMap(v interface{}) map[string]string {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}
