// Package ackinv defines the ACK controller inventory: a committed snapshot
// of every ACK service controller, its CRD kinds and their spec field paths.
// The inventory acts as a lockfile for schema-drift detection and lets CI
// validate that every control assertion path resolves against a real CRD
// field.
package ackinv

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Inventory is the root document persisted at mappings/ack/inventory.json.
// It intentionally carries no timestamp: regenerating against the same
// release tags must be byte-identical so diffs only reflect upstream change.
type Inventory struct {
	Org      string    `json:"org"`
	Services []Service `json:"services"`
}

// Service is one ACK service controller pinned to a release tag.
type Service struct {
	Name     string `json:"name"`
	Repo     string `json:"repo"`
	Release  string `json:"release"`
	FullName string `json:"fullName,omitempty"`
	Kinds    []Kind `json:"kinds"`
}

// Kind is one CRD exposed by a controller.
type Kind struct {
	Kind     string   `json:"kind"`
	Group    string   `json:"group"`
	Versions []string `json:"versions"`
	Fields   []Field  `json:"fields"`
}

// Field is a flattened spec field path. List descent is encoded with a "[]"
// suffix on the segment (e.g. "spec.encryption.rules[].sseAlgorithm"). Type
// is the leaf type: string, integer, number, boolean, object (no known
// properties), map (additionalProperties) or opaque
// (x-kubernetes-preserve-unknown-fields).
type Field struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// Load reads and parses an inventory file.
func Load(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading inventory: %w", err)
	}
	var inv Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parsing inventory %s: %w", path, err)
	}
	return &inv, nil
}

// Save writes the inventory with deterministic ordering and stable
// formatting so committed diffs are minimal and reviewable.
func Save(path string, inv *Inventory) error {
	inv.Sort()
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Sort orders services, kinds and fields deterministically and normalizes
// nil slices to empty so the JSON always uses [] rather than null.
func (inv *Inventory) Sort() {
	sort.Slice(inv.Services, func(i, j int) bool { return inv.Services[i].Name < inv.Services[j].Name })
	for si := range inv.Services {
		svc := &inv.Services[si]
		if svc.Kinds == nil {
			svc.Kinds = []Kind{}
		}
		sort.Slice(svc.Kinds, func(i, j int) bool { return svc.Kinds[i].Kind < svc.Kinds[j].Kind })
		for ki := range svc.Kinds {
			k := &svc.Kinds[ki]
			if k.Fields == nil {
				k.Fields = []Field{}
			}
			sort.Strings(k.Versions)
			sort.Slice(k.Fields, func(i, j int) bool { return k.Fields[i].Path < k.Fields[j].Path })
		}
	}
}

// KindsByGroup indexes all kinds by (lowercased group, lowercased kind).
func (inv *Inventory) KindsByGroup() map[string]map[string]*Kind {
	out := map[string]map[string]*Kind{}
	for si := range inv.Services {
		for ki := range inv.Services[si].Kinds {
			k := &inv.Services[si].Kinds[ki]
			g := strings.ToLower(k.Group)
			if out[g] == nil {
				out[g] = map[string]*Kind{}
			}
			out[g][strings.ToLower(k.Kind)] = k
		}
	}
	return out
}
