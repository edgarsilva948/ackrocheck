package ackinv

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// crdDoc mirrors the subset of apiextensions.k8s.io/v1 CustomResourceDefinition
// needed to extract kind, group and the spec schema.
type crdDoc struct {
	Kind string `yaml:"kind"`
	Spec struct {
		Group string `yaml:"group"`
		Names struct {
			Kind string `yaml:"kind"`
		} `yaml:"names"`
		Versions []struct {
			Name   string `yaml:"name"`
			Schema struct {
				OpenAPIV3Schema map[string]interface{} `yaml:"openAPIV3Schema"`
			} `yaml:"schema"`
		} `yaml:"versions"`
	} `yaml:"spec"`
}

// ParseCRD parses a CRD YAML document and returns the flattened Kind. CRDs
// with multiple versions use the schema of the last (newest) version, with
// all version names recorded.
func ParseCRD(data []byte) (*Kind, error) {
	var crd crdDoc
	if err := yaml.Unmarshal(data, &crd); err != nil {
		return nil, fmt.Errorf("parsing CRD: %w", err)
	}
	if crd.Kind != "CustomResourceDefinition" || crd.Spec.Names.Kind == "" {
		return nil, fmt.Errorf("not a CustomResourceDefinition (kind=%q)", crd.Kind)
	}
	if len(crd.Spec.Versions) == 0 {
		return nil, fmt.Errorf("CRD %s has no versions", crd.Spec.Names.Kind)
	}
	out := &Kind{
		Kind:  crd.Spec.Names.Kind,
		Group: crd.Spec.Group,
	}
	for _, v := range crd.Spec.Versions {
		out.Versions = append(out.Versions, v.Name)
	}
	schema := crd.Spec.Versions[len(crd.Spec.Versions)-1].Schema.OpenAPIV3Schema
	spec, _ := lookupMap(schema, "properties", "spec")
	if spec != nil {
		out.Fields = flattenSchema(spec, "spec", 0)
	}
	sort.Slice(out.Fields, func(i, j int) bool { return out.Fields[i].Path < out.Fields[j].Path })
	return out, nil
}

// maxDepth bounds recursion: ACK CRDs occasionally embed deeply nested or
// self-referential structures (e.g. WAFv2 rule statements); beyond this depth
// the field is recorded as opaque rather than expanded.
const maxDepth = 12

// flattenSchema walks an OpenAPI v3 schema node and emits one Field per leaf.
// List descent appends "[]" to the path segment. Maps (additionalProperties)
// and schemas with x-kubernetes-preserve-unknown-fields become single leaves
// of type "map"/"opaque" since their keys are not statically known.
func flattenSchema(node map[string]interface{}, path string, depth int) []Field {
	if depth > maxDepth {
		return []Field{{Path: path, Type: "opaque"}}
	}
	typ, _ := node["type"].(string)
	if preserve, ok := node["x-kubernetes-preserve-unknown-fields"].(bool); ok && preserve {
		return []Field{{Path: path, Type: "opaque"}}
	}
	switch typ {
	case "object", "":
		if props, ok := lookupMap(node, "properties"); ok && len(props) > 0 {
			var out []Field
			for name, raw := range props {
				child, ok := raw.(map[string]interface{})
				if !ok {
					continue
				}
				out = append(out, flattenSchema(child, path+"."+name, depth+1)...)
			}
			return out
		}
		if _, ok := node["additionalProperties"]; ok {
			return []Field{{Path: path, Type: "map"}}
		}
		return []Field{{Path: path, Type: "object"}}
	case "array":
		items, ok := lookupMap(node, "items")
		if !ok {
			return []Field{{Path: path + "[]", Type: "opaque"}}
		}
		return flattenSchema(items, path+"[]", depth+1)
	default:
		return []Field{{Path: path, Type: typ}}
	}
}

// lookupMap descends through nested map keys, returning the final map value.
func lookupMap(m map[string]interface{}, keys ...string) (map[string]interface{}, bool) {
	current := m
	for _, k := range keys {
		v, ok := current[k]
		if !ok {
			return nil, false
		}
		current, ok = v.(map[string]interface{})
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// HasPath reports whether a dot-separated assertion path (as used in control
// files, without "[]" markers) is consistent with the kind's flattened
// fields. Assertion paths address values at runtime where lists are entered
// element-wise, so "spec.encryption.rules" matches the flattened
// "spec.encryption.rules[].x" prefix, and a nested-assertion relative path is
// matched against the remainder after the list marker.
//
// A path is accepted when some flattened field path, after removing "[]"
// markers, equals the assertion path or is prefixed by it at a segment
// boundary. Paths under map/opaque fields are accepted (keys unknown
// statically).
func (k *Kind) HasPath(path string) bool {
	if path == "." || strings.HasPrefix(path, NormalizedPrefix) {
		return true
	}
	for _, f := range k.Fields {
		plain := strings.ReplaceAll(f.Path, "[]", "")
		if plain == path || strings.HasPrefix(plain, path+".") {
			return true
		}
		// Paths descending below a map/opaque leaf cannot be validated.
		if (f.Type == "map" || f.Type == "opaque" || f.Type == "object") && strings.HasPrefix(path, plain+".") {
			return true
		}
	}
	return false
}

// NormalizedPrefix is the synthetic document prefix injected by the scanner
// for parsed IAM policy documents; such paths do not exist in CRD schemas.
const NormalizedPrefix = "__ackrocheck."
