// Package parser reads Kubernetes manifests from files and directories into
// resource documents that the scanner can evaluate.
package parser

import (
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

// MaxFileSize is the largest manifest file the parser will read (16 MiB).
// Manifests larger than this are reported as parse errors, not scanned.
const MaxFileSize = 16 << 20

// Resource is a single parsed YAML document from a manifest file.
type Resource struct {
	APIVersion  string
	Kind        string
	Name        string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
	// Spec is the raw spec block, if present.
	Spec map[string]interface{}
	// Raw is the full decoded document.
	Raw map[string]interface{}
	// FilePath is the path of the file the document was read from.
	FilePath string
	// DocIndex is the zero-based index of the document within the file.
	DocIndex int
	// Line is the 1-based line where the document starts (0 if unknown).
	Line int
}

// APIGroup returns the group portion of apiVersion ("" for core resources).
func (r *Resource) APIGroup() string {
	if i := strings.Index(r.APIVersion, "/"); i >= 0 {
		return r.APIVersion[:i]
	}
	return ""
}

// ParseError records a file that could not be parsed. Scanning continues for
// other files.
type ParseError struct {
	FilePath string
	Err      error
}

func (e ParseError) Error() string {
	return fmt.Sprintf("%s: %v", e.FilePath, e.Err)
}

// Result holds the outcome of parsing a set of paths.
type Result struct {
	Resources []Resource
	Errors    []ParseError
	// FilesScanned is the number of YAML files read (including failed ones).
	FilesScanned int
}

var yamlExtensions = map[string]bool{".yaml": true, ".yml": true}

// ParsePaths reads each path (file or directory, directories recursively) and
// returns all parsed resources. Malformed files are recorded in Result.Errors
// and do not stop the scan.
func ParsePaths(paths []string) (*Result, error) {
	res := &Result{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("cannot access %s: %w", p, err)
		}
		if info.IsDir() {
			if err := parseDir(p, res); err != nil {
				return nil, err
			}
		} else {
			parseFileInto(p, res)
		}
	}
	sortResources(res.Resources)
	sort.Slice(res.Errors, func(i, j int) bool { return res.Errors[i].FilePath < res.Errors[j].FilePath })
	return res, nil
}

func parseDir(dir string, res *Result) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking %s: %w", path, err)
		}
		if d.IsDir() {
			// Skip hidden directories such as .git.
			if name := d.Name(); name != "." && strings.HasPrefix(name, ".") && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if !yamlExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		parseFileInto(path, res)
		return nil
	})
}

func parseFileInto(path string, res *Result) {
	res.FilesScanned++
	resources, err := ParseFile(path)
	if err != nil {
		res.Errors = append(res.Errors, ParseError{FilePath: path, Err: err})
		return
	}
	res.Resources = append(res.Resources, resources...)
}

// ParseFile parses a single multi-document YAML file.
func ParseFile(path string) ([]Resource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("file is %d bytes, larger than the %d byte limit", info.Size(), int64(MaxFileSize))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	// Close error is irrelevant for a file opened read-only.
	defer func() { _ = f.Close() }()
	return parseReader(f, path)
}

func parseReader(r io.Reader, path string) ([]Resource, error) {
	dec := yaml.NewDecoder(r)
	var resources []Resource
	for docIndex := 0; ; docIndex++ {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", docIndex, err)
		}
		var raw map[string]interface{}
		if err := node.Decode(&raw); err != nil {
			// Non-mapping documents (scalars, lists, null) are skipped: they
			// cannot be Kubernetes resources.
			continue
		}
		if raw == nil {
			continue
		}
		res := buildResource(raw, path, docIndex)
		res.Line = node.Line
		resources = append(resources, res)
	}
	return resources, nil
}

func buildResource(raw map[string]interface{}, path string, docIndex int) Resource {
	r := Resource{
		Raw:      raw,
		FilePath: path,
		DocIndex: docIndex,
	}
	r.APIVersion, _ = raw["apiVersion"].(string)
	r.Kind, _ = raw["kind"].(string)
	if meta, ok := raw["metadata"].(map[string]interface{}); ok {
		r.Name, _ = meta["name"].(string)
		r.Namespace, _ = meta["namespace"].(string)
		r.Labels = stringMap(meta["labels"])
		r.Annotations = stringMap(meta["annotations"])
	}
	if spec, ok := raw["spec"].(map[string]interface{}); ok {
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
		switch s := val.(type) {
		case string:
			out[k] = s
		case bool:
			out[k] = fmt.Sprintf("%t", s)
		case int:
			out[k] = fmt.Sprintf("%d", s)
		case float64:
			out[k] = strings.TrimSuffix(fmt.Sprintf("%v", s), ".0")
		}
	}
	return out
}

func sortResources(rs []Resource) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].FilePath != rs[j].FilePath {
			return rs[i].FilePath < rs[j].FilePath
		}
		return rs[i].DocIndex < rs[j].DocIndex
	})
}
