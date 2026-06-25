// Package stix exports a Threagile analysis as a STIX 2.1 bundle for interop
// with threat-intelligence platforms (TIPs), the OASIS ecosystem, and tools like
// the ATT&CK Navigator / OpenCTI. The export is fully deterministic: object IDs
// are UUIDv5 derived from stable seeds (synthetic risk IDs, asset IDs) and
// timestamps are a fixed reference value, so the same model always yields
// byte-identical output (diffable in CI).
package stix

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/threagile/threagile/pkg/attack"
	"github.com/threagile/threagile/pkg/types"
)

// stixNamespace is a fixed UUID namespace for deterministic UUIDv5 object IDs.
var stixNamespace = uuid.MustParse("6ba7b814-9dad-11d1-80b4-00c04fd430c8")

// fixedTimestamp keeps created/modified stable for reproducible, diffable output.
const fixedTimestamp = "2020-01-01T00:00:00.000Z"

// Object is a STIX 2.1 Domain or Relationship Object (only the fields we emit).
type Object struct {
	Type                string        `json:"type"`
	SpecVersion         string        `json:"spec_version"`
	ID                  string        `json:"id"`
	Created             string        `json:"created"`
	Modified            string        `json:"modified"`
	Name                string        `json:"name,omitempty"`
	Description         string        `json:"description,omitempty"`
	IdentityClass       string        `json:"identity_class,omitempty"`
	InfrastructureTypes []string      `json:"infrastructure_types,omitempty"`
	ExternalReferences  []ExternalRef `json:"external_references,omitempty"`
	// Relationship-only fields.
	RelationshipType string `json:"relationship_type,omitempty"`
	SourceRef        string `json:"source_ref,omitempty"`
	TargetRef        string `json:"target_ref,omitempty"`
}

type ExternalRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id,omitempty"`
	URL        string `json:"url,omitempty"`
}

// Bundle is the top-level STIX 2.1 bundle.
type Bundle struct {
	Type    string   `json:"type"`
	ID      string   `json:"id"`
	Objects []Object `json:"objects"`
}

// Result wraps the bundle plus a small summary.
type Result struct {
	Bundle             Bundle
	UnmappedCategories []string
}

func id(typeName, seed string) string {
	u := uuid.NewSHA1(stixNamespace, []byte(typeName+":"+seed))
	return typeName + "--" + u.String()
}

func (b *Bundle) add(typeName, seed string, mutate func(*Object)) string {
	objID := id(typeName, seed)
	o := Object{Type: typeName, SpecVersion: "2.1", ID: objID, Created: fixedTimestamp, Modified: fixedTimestamp}
	if mutate != nil {
		mutate(&o)
	}
	b.Objects = append(b.Objects, o)
	return objID
}

// Build produces a STIX 2.1 bundle from the analyzed model and its risks.
func Build(model *types.Model, risks []*types.Risk) *Result {
	// Seed the bundle ID with the title plus model size so two distinct models
	// that share a title don't collide on the same bundle id.
	bundleSeed := fmt.Sprintf("bundle:%s:%d:%d", model.Title, len(model.TechnicalAssets), len(risks))
	bundle := Bundle{Type: "bundle", ID: "bundle--" + uuid.NewSHA1(stixNamespace, []byte(bundleSeed)).String()}

	// Identity for the threat model itself.
	bundle.add("identity", "model:"+model.Title, func(o *Object) {
		o.Name = orDefault(model.Title, "Threat Model")
		o.IdentityClass = "system"
		o.Description = "Threagile threat model"
	})

	// Infrastructure SDO per technical asset (sorted for determinism).
	assetSTIXID := map[string]string{}
	for _, assetID := range sortedKeys(model.TechnicalAssets) {
		a := model.TechnicalAssets[assetID]
		sid := bundle.add("infrastructure", assetID, func(o *Object) {
			o.Name = orDefault(a.Title, assetID)
			o.Description = a.Description
			o.InfrastructureTypes = []string{"unknown"}
		})
		assetSTIXID[assetID] = sid
	}

	unmapped := map[string]bool{}
	patternSTIXID := map[string]string{} // technique/capec id -> stix attack-pattern id
	rels := map[string]bool{}            // dedupe relationships by (type,src,tgt)
	addRel := func(relType, src, tgt string) {
		if src == "" || tgt == "" {
			return
		}
		key := relType + "|" + src + "|" + tgt
		if rels[key] {
			return
		}
		rels[key] = true
		bundle.add("relationship", key, func(o *Object) {
			o.RelationshipType = relType
			o.SourceRef = src
			o.TargetRef = tgt
		})
	}
	ensurePattern := func(refID string) string {
		if sid, ok := patternSTIXID[refID]; ok {
			return sid
		}
		sid := bundle.add("attack-pattern", refID, func(o *Object) {
			o.Name = patternName(refID)
			o.ExternalReferences = []ExternalRef{patternRef(refID)}
		})
		patternSTIXID[refID] = sid
		return sid
	}

	categoriesSeen := map[string]bool{}
	for _, r := range sortedRisks(risks) {
		assetSID := assetSTIXID[r.MostRelevantTechnicalAssetId]

		// Vulnerability SDO per risk.
		vulnSID := bundle.add("vulnerability", r.SyntheticId, func(o *Object) {
			o.Name = orDefault(r.Title, r.SyntheticId)
			o.Description = strings.Join(r.RiskExplanation, " ")
			if cat := model.GetRiskCategory(r.CategoryId); cat != nil && cat.CWE > 0 {
				o.ExternalReferences = []ExternalRef{{
					SourceName: "cwe",
					ExternalID: fmt.Sprintf("CWE-%d", cat.CWE),
					URL:        fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", cat.CWE),
				}}
			}
		})
		// STIX 2.1 spec relationship: infrastructure "has" vulnerability.
		addRel("has", assetSID, vulnSID)

		// Attack-pattern SDOs (ATT&CK + CAPEC). attack-pattern "targets" a
		// vulnerability (the spec allows identity/location/vulnerability targets,
		// not infrastructure), so relate the pattern to the vulnerability.
		for _, tech := range attack.CategoryTechniques[r.CategoryId] {
			addRel("targets", ensurePattern(tech), vulnSID)
		}
		for _, capec := range attack.CategoryCAPEC[r.CategoryId] {
			addRel("targets", ensurePattern(capec), vulnSID)
		}
		if len(attack.CategoryTechniques[r.CategoryId]) == 0 && len(attack.CategoryCAPEC[r.CategoryId]) == 0 {
			unmapped[r.CategoryId] = true
		}

		// Course-of-action SDO per category (mitigation), once.
		if !categoriesSeen[r.CategoryId] {
			categoriesSeen[r.CategoryId] = true
			if cat := model.GetRiskCategory(r.CategoryId); cat != nil {
				if mit := orDefault(cat.Mitigation, cat.Action); mit != "" {
					coaSID := bundle.add("course-of-action", "mitigation:"+r.CategoryId, func(o *Object) {
						o.Name = orDefault(cat.Title, r.CategoryId) + " — mitigation"
						o.Description = mit
					})
					addRel("mitigates", coaSID, vulnSID)
				}
			}
		} else if cat := model.GetRiskCategory(r.CategoryId); cat != nil {
			if orDefault(cat.Mitigation, cat.Action) != "" {
				addRel("mitigates", id("course-of-action", "mitigation:"+r.CategoryId), vulnSID)
			}
		}
	}

	return &Result{Bundle: bundle, UnmappedCategories: sortedSet(unmapped)}
}

// patternName resolves a human-readable name for an ATT&CK technique or CAPEC id,
// falling back to the raw ID so the required STIX `name` is never empty.
func patternName(refID string) string {
	var name string
	if strings.HasPrefix(refID, "CAPEC-") {
		name = attack.CAPECName(refID)
	} else {
		name = attack.TechniqueName(refID)
	}
	if name == "" {
		return refID
	}
	return name
}

// patternRef builds the STIX external reference for an ATT&CK technique or CAPEC id.
func patternRef(refID string) ExternalRef {
	if strings.HasPrefix(refID, "CAPEC-") {
		return ExternalRef{
			SourceName: "capec",
			ExternalID: refID,
			URL:        "https://capec.mitre.org/data/definitions/" + attack.CAPECNumber(refID) + ".html",
		}
	}
	// ATT&CK technique; sub-techniques (T1078.001) use a slash in the URL.
	urlPath := strings.ReplaceAll(refID, ".", "/")
	return ExternalRef{
		SourceName: "mitre-attack",
		ExternalID: refID,
		URL:        "https://attack.mitre.org/techniques/" + urlPath,
	}
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func sortedKeys(m map[string]*types.TechnicalAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedRisks(risks []*types.Risk) []*types.Risk {
	out := append([]*types.Risk{}, risks...)
	sort.Slice(out, func(i, j int) bool { return out[i].SyntheticId < out[j].SyntheticId })
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
