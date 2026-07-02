package mapping

import (
	"testing"

	"github.com/threagile/threagile/pkg/types"
)

func mustParse(t *testing.T, data string) *Ruleset {
	t.Helper()
	rs, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	return rs
}

func TestResolveFirstMatchWinsPerScalarField(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { label: '(?i)minio' }
    set: { technology: object-storage }
  - match: { label: '(?i)minio' }
    set: { technology: should-not-win }
`)
	got := rs.Resolve(Element{Label: "MinIO Bucket"})
	if got.Technology != "object-storage" {
		t.Fatalf("expected first matching rule to win, got %q", got.Technology)
	}
}

func TestResolveTagsAccumulateAcrossMatches(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { label: '(?i)minio' }
    set: { tags: [a, b] }
  - match: { label: '(?i)bucket' }
    set: { tags: [b, c] }
`)
	got := rs.Resolve(Element{Label: "MinIO Bucket"})
	want := map[string]bool{"a": true, "b": true, "c": true}
	if len(got.Tags) != 3 {
		t.Fatalf("expected 3 deduplicated tags, got %v", got.Tags)
	}
	for _, tag := range got.Tags {
		if !want[tag] {
			t.Fatalf("unexpected tag %q in %v", tag, got.Tags)
		}
	}
}

func TestResolveLabelRegexCaseInsensitive(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { label: '(?i)minio|blob' }
    set: { technology: object-storage }
`)
	if rs.Resolve(Element{Label: "minio-bucket"}).Technology != "object-storage" {
		t.Fatalf("expected lowercase label to match")
	}
	if rs.Resolve(Element{Label: "MINIO-BUCKET"}).Technology != "object-storage" {
		t.Fatalf("expected uppercase label to match (?i)")
	}
	if rs.Resolve(Element{Label: "postgres"}).Technology != "" {
		t.Fatalf("expected non-matching label to resolve to nothing")
	}
}

func TestResolveEdgeMatcher(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { edge: true, color: '#FF0000' }
    set: { encryption: none, tags: [flagged-unencrypted] }
`)
	edge := rs.Resolve(Element{Edge: true, Color: "#FF0000"})
	if edge.Encryption != "none" {
		t.Fatalf("expected edge+color match to set encryption, got %+v", edge)
	}
	notEdge := rs.Resolve(Element{Edge: false, Color: "#FF0000"})
	if notEdge.Encryption != "" {
		t.Fatalf("expected vertex (edge=false) not to match an edge:true rule, got %+v", notEdge)
	}
	wrongColor := rs.Resolve(Element{Edge: true, Color: "#00FF00"})
	if wrongColor.Encryption != "" {
		t.Fatalf("expected mismatched color not to match, got %+v", wrongColor)
	}
	noColorAtAll := rs.Resolve(Element{Edge: true})
	if noColorAtAll.Encryption != "" {
		t.Fatalf("expected an element with no color data to never match a color matcher, got %+v", noColorAtAll)
	}
}

func TestResolveFillColorMatcher(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { fill_color: '#00AA00' }
    set: { trust_boundary: internal }
`)
	got := rs.Resolve(Element{FillColor: "#00aa00"})
	if got.TrustBoundary != "internal" {
		t.Fatalf("expected case-insensitive fill_color match, got %+v", got)
	}
}

func TestApplyToTechnicalAssetSetsRecognisedFields(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { label: '(?i)minio' }
    set:
      type: datastore
      technology: object-storage
      machine: virtual
      confidentiality: strictly-confidential
      integrity: mission-critical
      availability: critical
      tags: [object-store]
`)
	asset := &types.TechnicalAsset{Title: "MinIO Bucket", Type: types.Process}
	ApplyToTechnicalAsset(rs, asset, Element{Label: asset.Title})

	if asset.Type != types.Datastore {
		t.Fatalf("expected type=datastore, got %v", asset.Type)
	}
	if len(asset.Technologies) != 1 || asset.Technologies[0].Name != "object-storage" {
		t.Fatalf("expected technology=object-storage, got %+v", asset.Technologies)
	}
	if asset.Machine != types.Virtual {
		t.Fatalf("expected machine=virtual, got %v", asset.Machine)
	}
	if asset.Confidentiality != types.StrictlyConfidential {
		t.Fatalf("expected confidentiality=strictly-confidential, got %v", asset.Confidentiality)
	}
	if asset.Integrity != types.MissionCritical {
		t.Fatalf("expected integrity=mission-critical, got %v", asset.Integrity)
	}
	found := false
	for _, tag := range asset.Tags {
		if tag == "object-store" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected tag object-store in %v", asset.Tags)
	}
}

func TestApplyToTechnicalAssetTechnologiesList(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { label: 'multi' }
    set:
      technologies: [web-server, load-balancer]
`)
	asset := &types.TechnicalAsset{Title: "multi-tech"}
	ApplyToTechnicalAsset(rs, asset, Element{Label: asset.Title})
	if len(asset.Technologies) != 2 {
		t.Fatalf("expected 2 technologies, got %+v", asset.Technologies)
	}
}

func TestApplyToTechnicalAssetInvalidEnumIsSkipped(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { label: 'x' }
    set: { type: not-a-real-type }
`)
	asset := &types.TechnicalAsset{Title: "x", Type: types.Process}
	ApplyToTechnicalAsset(rs, asset, Element{Label: "x"})
	if asset.Type != types.Process {
		t.Fatalf("expected invalid type to be silently skipped, got %v", asset.Type)
	}
}

func TestApplyToTechnicalAssetTrustBoundaryBecomesTag(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { label: 'x' }
    set: { trust_boundary: internal }
`)
	asset := &types.TechnicalAsset{Title: "x"}
	ApplyToTechnicalAsset(rs, asset, Element{Label: "x"})
	if len(asset.Tags) != 1 || asset.Tags[0] != "trust:internal" {
		t.Fatalf("expected trust:internal tag, got %v", asset.Tags)
	}
}

func TestApplyToTechnicalAssetNilSafe(t *testing.T) {
	ApplyToTechnicalAsset(nil, &types.TechnicalAsset{}, Element{})
	ApplyToTechnicalAsset(mustParse(t, "rules:\n  - match: {label: x}\n    set: {technology: y}\n"), nil, Element{})
}

func TestApplyToDataAsset(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { label: 'secret' }
    set: { confidentiality: strictly-confidential, tags: [pii] }
`)
	da := &types.DataAsset{Title: "secret-data"}
	ApplyToDataAsset(rs, da, Element{Label: da.Title})
	if da.Confidentiality != types.StrictlyConfidential {
		t.Fatalf("expected strictly-confidential, got %v", da.Confidentiality)
	}
	if len(da.Tags) != 1 || da.Tags[0] != "pii" {
		t.Fatalf("expected pii tag, got %v", da.Tags)
	}
}

func TestApplyToCommunicationLinkEncryptionBecomesTag(t *testing.T) {
	rs := mustParse(t, `
rules:
  - match: { edge: true, color: '#FF0000' }
    set: { encryption: none, tags: [flagged-unencrypted] }
`)
	link := &types.CommunicationLink{Title: "flow"}
	ApplyToCommunicationLink(rs, link, Element{Label: "flow", Edge: true, Color: "#FF0000"})
	wantTags := map[string]bool{"flagged-unencrypted": true, "encryption:none": true}
	if len(link.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", link.Tags)
	}
	for _, tag := range link.Tags {
		if !wantTags[tag] {
			t.Fatalf("unexpected tag %q in %v", tag, link.Tags)
		}
	}
}

func TestApplyNilSafeEverywhere(t *testing.T) {
	// Must not panic regardless of nil ruleset/target combinations.
	ApplyToTechnicalAsset(nil, nil, Element{})
	ApplyToDataAsset(nil, nil, Element{})
	ApplyToCommunicationLink(nil, nil, Element{})
}

func TestAppendTagsDeduplicates(t *testing.T) {
	dst := []string{"existing"}
	appendTags(&dst, []string{"existing", "new"})
	if len(dst) != 2 {
		t.Fatalf("expected no duplicate of 'existing', got %v", dst)
	}
}
