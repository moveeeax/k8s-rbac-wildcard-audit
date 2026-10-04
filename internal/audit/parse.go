package audit

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

// rbacKinds are the only kinds this tool reads. Everything else in a manifest
// stream is skipped without comment — pointing the tool at a whole chart
// render is the normal case, not an error.
var rbacKinds = map[string]bool{
	"Role":        true,
	"ClusterRole": true,
}

// StdinPath is the positional argument that means "read the manifest stream
// from stdin", so `helm template . | k8s-rbac-wildcard-audit -` works.
const StdinPath = "-"

// Decode pulls every Role and ClusterRole out of a (possibly multi-document)
// YAML stream. Documents that are not RBAC, and documents whose shape does not
// match a Role at all, are dropped quietly; a YAML syntax error is returned.
func Decode(r io.Reader, file string) ([]Object, error) {
	dec := yaml.NewDecoder(r)
	var out []Object
	for i := 0; ; i++ {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("%s: document %d: %w", file, i, err)
		}
		// `---` with nothing after it decodes to a zero node.
		if node.Kind == 0 {
			continue
		}
		var probe struct {
			Kind string `yaml:"kind"`
		}
		if err := node.Decode(&probe); err != nil {
			continue // not a mapping with a kind: not our business
		}
		if !rbacKinds[probe.Kind] {
			continue
		}
		var obj Object
		if err := node.Decode(&obj); err != nil {
			// Kind says Role but the body is unusable. Worth surfacing: a
			// silently skipped ClusterRole is exactly the failure mode this
			// tool exists to prevent.
			return out, fmt.Errorf("%s: document %d: %s: %w", file, i, probe.Kind, err)
		}
		obj.File = file
		obj.DocIndex = i
		out = append(out, obj)
	}
}

// DecodeFile reads one manifest file, or stdin when path is "-".
func DecodeFile(path string) ([]Object, error) {
	if path == StdinPath {
		return Decode(os.Stdin, "<stdin>")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Decode(f, path)
}

// CollectFiles expands the positional arguments into a sorted file list.
// Directories are walked for .yaml/.yml; an explicit file path is taken as
// given whatever its extension, and "-" is passed through.
func CollectFiles(paths []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range paths {
		if p == StdinPath {
			add(p)
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			add(p)
			continue
		}
		var found []string
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Vendored charts and .git are noise, never policy under review.
				if n := d.Name(); n == ".git" || n == "vendor" || n == "charts" {
					return fs.SkipDir
				}
				return nil
			}
			if isYAML(path) {
				found = append(found, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(found)
		for _, f := range found {
			add(f)
		}
	}
	return out, nil
}

func isYAML(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return true
	}
	return false
}
