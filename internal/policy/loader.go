package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFS loads every *.yaml policy under root in the given filesystem.
// Policies are validated; an invalid policy fails the whole load so broken
// controls are never silently skipped.
func LoadFS(fsys fs.FS, root string) ([]Policy, error) {
	var policies []Policy
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading policy %s: %w", path, err)
		}
		ps, err := parsePolicies(data, path)
		if err != nil {
			return err
		}
		policies = append(policies, ps...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := checkDuplicates(policies); err != nil {
		return nil, err
	}
	sortPolicies(policies)
	return policies, nil
}

// LoadDir loads external policies from a local directory. Only the given
// directory tree is read.
func LoadDir(dir string) ([]Policy, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot access controls directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		// Allow a single policy file as well.
		data, err := os.ReadFile(dir)
		if err != nil {
			return nil, fmt.Errorf("reading policy %s: %w", dir, err)
		}
		ps, err := parsePolicies(data, dir)
		if err != nil {
			return nil, err
		}
		sortPolicies(ps)
		return ps, nil
	}
	return LoadFS(os.DirFS(dir), ".")
}

// Merge combines built-in and external policies. External policies may not
// reuse a built-in control ID: built-in IDs are stable and must never be
// silently redefined.
func Merge(builtin, external []Policy) ([]Policy, error) {
	ids := make(map[string]bool, len(builtin))
	for _, p := range builtin {
		ids[p.ID] = true
	}
	merged := append([]Policy{}, builtin...)
	for _, p := range external {
		if ids[p.ID] {
			return nil, fmt.Errorf("external policy %s redefines a built-in control; built-in control IDs are stable and cannot be overridden", p.ID)
		}
		ids[p.ID] = true
		merged = append(merged, p)
	}
	sortPolicies(merged)
	return merged, nil
}

func parsePolicies(data []byte, path string) ([]Policy, error) {
	var policies []Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for docIndex := 0; ; docIndex++ {
		var p Policy
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("policy file %s document %d: %w", path, docIndex, err)
		}
		if p.ID == "" && p.Title == "" && len(p.Assertions) == 0 {
			continue // empty document
		}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("policy file %s: %w", path, err)
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func checkDuplicates(policies []Policy) error {
	seen := map[string]bool{}
	for _, p := range policies {
		if seen[p.ID] {
			return fmt.Errorf("duplicate policy id %s", p.ID)
		}
		seen[p.ID] = true
	}
	return nil
}

func sortPolicies(ps []Policy) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
