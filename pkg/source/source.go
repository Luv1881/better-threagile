// Package source maps named model entities (technical assets, data assets, …)
// to their location in the model YAML, following the fork's includes: directive,
// so diagnostics and reports can point at the exact file:line to fix.
//
// It imports nothing from the rest of the project (only yaml.v3), so any package
// — internal CLI or pkg/* — can use it without import cycles.
package source

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Location is where a named entity is defined. File is "" for the main model
// file and the include's base name for entities pulled in via includes:.
type Location struct {
	File string
	Line int
}

// String renders a compact source location: "file:line", or "line N" for the
// main file. The zero value renders "line 0"; callers should check Line > 0.
func (l Location) String() string {
	if l.File != "" {
		return fmt.Sprintf("%s:%d", l.File, l.Line)
	}
	return fmt.Sprintf("line %d", l.Line)
}

var entitySections = map[string]bool{
	"technical_assets": true, "data_assets": true, "trust_boundaries": true,
	"shared_runtimes": true, "threat_scenarios": true, "business_processes": true,
}

// EntityLines maps each top-level named entity to its Location, keyed by BOTH
// the YAML title (the map key) and the entity's nested id: value — so a caller
// that has either identifier can resolve a location. On the (astronomically
// unlikely) collision of an id with a different entity's title, the title wins.
// The includes: directive is followed one level deep. Best-effort: returns an
// empty map on any read/parse error so callers degrade gracefully.
func EntityLines(modelFile string) map[string]Location {
	titleLocs := map[string]Location{}
	idLocs := map[string]Location{}
	baseDir := filepath.Dir(modelFile)

	var scan func(path, label string, followIncludes bool)
	scan = func(path, label string, followIncludes bool) {
		data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied model path
		if err != nil {
			return
		}
		var root yaml.Node
		if err := yaml.Unmarshal(data, &root); err != nil || len(root.Content) == 0 {
			return
		}
		doc := root.Content[0]
		if doc.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(doc.Content); i += 2 {
			key, val := doc.Content[i], doc.Content[i+1]
			if key.Value == "includes" && followIncludes && val.Kind == yaml.SequenceNode {
				for _, inc := range val.Content {
					if inc.Value != "" {
						scan(filepath.Join(baseDir, inc.Value), filepath.Base(inc.Value), false)
					}
				}
				continue
			}
			if !entitySections[key.Value] || val.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(val.Content); j += 2 {
				titleNode, entityNode := val.Content[j], val.Content[j+1]
				if titleNode.Value == "" {
					continue
				}
				loc := Location{File: label, Line: titleNode.Line}
				if _, exists := titleLocs[titleNode.Value]; !exists {
					titleLocs[titleNode.Value] = loc
				}
				if entityNode.Kind == yaml.MappingNode {
					if id := childValue(entityNode, "id"); id != "" {
						if _, exists := idLocs[id]; !exists {
							idLocs[id] = loc
						}
					}
				}
			}
		}
	}
	scan(modelFile, "", true)

	// Merge id keys first, then overlay title keys so titles win on collision.
	merged := make(map[string]Location, len(titleLocs)+len(idLocs))
	for k, v := range idLocs {
		merged[k] = v
	}
	for k, v := range titleLocs {
		merged[k] = v
	}
	return merged
}

// childValue returns the scalar value of a child key in a mapping node, or "".
func childValue(m *yaml.Node, key string) string {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1].Value
		}
	}
	return ""
}
