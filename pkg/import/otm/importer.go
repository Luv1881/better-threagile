// Package otm converts an Open Threat Model (OTM) JSON document — the
// IriusRisk-led open interchange format — into a partial Threagile model.
// This is a fully deterministic, near-lossless conversion (no AI): trust
// zones become trust boundaries (with nesting via each zone's
// parent.trustZone reference), components become technical assets
// (classified by their OTM `type` field via a deterministic lookup table),
// dataflows become communication links, and OTM `assets` — which, unlike
// pure diagram formats, actually carry data — become data assets. Every
// generated element is tagged "review-otm" for manual review.
//
//	model, err := otm.Import(jsonBytes, otm.ImportOptions{})
package otm

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/import/jsonerr"
	"github.com/threagile/threagile/pkg/import/mapping"
	"github.com/threagile/threagile/pkg/types"
)

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func toID(parts ...string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(strings.Join(parts, "-")), "-"), "-")
}

// ImportOptions controls import behaviour.
type ImportOptions struct {
	// SourceLabel is appended to generated asset IDs (default "otm").
	SourceLabel string

	// Mapping is an optional user-supplied mapping dictionary (P3) applied to
	// every component/dataflow right after it is classified, so corrections
	// land before P4 stub generation runs on the resulting model. OTM JSON
	// carries no style/color metadata, so only Mapping's label matcher will
	// ever fire here. nil means no mapping rules are applied.
	Mapping *mapping.Ruleset
}

// reviewTag flags every imported element for manual review.
const reviewTag = "review-otm"

// componentTypeRule maps an OTM component `type` substring to a Threagile
// technical asset type + technology, ordered so the first match wins
// (deterministic, same spirit as the threatdragon/drawio datastoreNames
// tables).
type componentTypeRule struct {
	needle    string
	assetType types.TechnicalAssetType
	tech      string
}

var componentTypeRules = []componentTypeRule{
	{"load-balancer", types.Process, types.LoadBalancer},
	{"reverse-proxy", types.Process, types.ReverseProxy},
	{"api-gateway", types.Process, types.Gateway},
	{"gateway", types.Process, types.Gateway},
	{"firewall", types.Process, types.Gateway},
	{"waf", types.Process, types.WAF},
	{"cdn", types.Process, types.ReverseProxy},
	{"identity-provider", types.Process, types.IdentityProvider},
	{"authentication", types.Process, types.IdentityProvider},
	{"message-broker", types.Datastore, types.MessageQueue},
	{"queue", types.Datastore, types.MessageQueue},
	{"cache", types.Datastore, types.Database},
	{"data-store", types.Datastore, types.Database},
	{"datastore", types.Datastore, types.Database},
	{"database", types.Datastore, types.Database},
	{"blob-storage", types.Datastore, types.FileServer},
	{"object-storage", types.Datastore, types.FileServer},
	{"file-storage", types.Datastore, types.FileServer},
	{"file-server", types.Datastore, types.FileServer},
	{"mobile-client", types.ExternalEntity, types.MobileApp},
	{"browser-client", types.ExternalEntity, types.Browser},
	{"human-user", types.ExternalEntity, types.ClientSystem},
	{"actor", types.ExternalEntity, types.ClientSystem},
	{"external-entity", types.ExternalEntity, types.ClientSystem},
	{"client", types.ExternalEntity, types.ClientSystem},
	{"web-application", types.Process, types.WebApplication},
	{"web-service", types.Process, types.WebServiceREST},
	{"web-server", types.Process, types.WebServer},
	{"function", types.Process, types.Function},
	{"serverless", types.Process, types.Function},
	{"iot", types.Process, types.IoTDevice},
	{"mobile", types.Process, types.MobileApp},
	{"application", types.Process, types.WebApplication},
}

// classifyComponent maps an OTM component type string to a Threagile
// technical asset type + technology. Unrecognised/empty types default to
// Process/UnknownTechnology so import never fails on custom nomenclature.
func classifyComponent(componentType string) (types.TechnicalAssetType, string) {
	t := strings.ToLower(strings.TrimSpace(componentType))
	for _, rule := range componentTypeRules {
		if strings.Contains(t, rule.needle) {
			return rule.assetType, rule.tech
		}
	}
	return types.Process, types.UnknownTechnology
}

// ratingBuckets maps a 0-100 OTM risk score onto one of 5 ordinal buckets
// (matching the 5-value Confidentiality/Criticality enums), rounding down so
// 100 lands in the top bucket.
func ratingBucket(score int) int {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	bucket := score / 20
	if bucket > 4 {
		bucket = 4
	}
	return bucket
}

func confidentialityFromScore(score *int) types.Confidentiality {
	if score == nil {
		return types.Confidential
	}
	return types.Confidentiality(ratingBucket(*score))
}

func criticalityFromScore(score *int) types.Criticality {
	if score == nil {
		return types.Critical
	}
	return types.Criticality(ratingBucket(*score))
}

// Import parses an OTM JSON document and returns a partial *types.Model.
func Import(data []byte, opts ImportOptions) (*types.Model, error) {
	if opts.SourceLabel == "" {
		opts.SourceLabel = "otm"
	}

	var doc otmDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("otm: failed to parse JSON: %w", jsonerr.WithPosition(data, err))
	}

	title := doc.Project.Name
	if strings.TrimSpace(title) == "" {
		title = "Imported from OTM"
	}

	model := &types.Model{
		ThreagileVersion:   "1.0.0",
		Title:              title,
		TechnicalAssets:    make(map[string]*types.TechnicalAsset),
		TrustBoundaries:    make(map[string]*types.TrustBoundary),
		DataAssets:         make(map[string]*types.DataAsset),
		CommunicationLinks: make(map[string]*types.CommunicationLink),
		TagsAvailable:      []string{reviewTag},
	}

	b := &builder{model: model, label: opts.SourceLabel, zoneAssetID: map[string]string{}, compAssetID: map[string]string{}, mapping: opts.Mapping}

	// Sort every OTM collection by ID up front so map iteration order in the
	// source JSON never affects the generated IDs/ordering (determinism).
	zones := append([]otmZone{}, doc.TrustZones...)
	sort.SliceStable(zones, func(i, j int) bool { return zones[i].Id < zones[j].Id })
	comps := append([]otmComp{}, doc.Components...)
	sort.SliceStable(comps, func(i, j int) bool { return comps[i].Id < comps[j].Id })
	flows := append([]otmFlow{}, doc.Dataflows...)
	sort.SliceStable(flows, func(i, j int) bool { return flows[i].Id < flows[j].Id })
	assets := append([]otmAsset{}, doc.Assets...)
	sort.SliceStable(assets, func(i, j int) bool { return assets[i].Id < assets[j].Id })

	for i := range zones {
		b.buildTrustBoundary(zones[i])
	}
	b.nestTrustBoundaries(zones)

	for i := range comps {
		b.buildTechnicalAsset(comps[i])
	}
	b.assignComponentsToZones(comps)

	for i := range flows {
		b.buildCommunicationLink(flows[i])
	}

	for i := range assets {
		b.buildDataAsset(assets[i])
	}

	if len(model.TechnicalAssets) == 0 {
		return nil, errors.New("otm: no components found in the OTM document")
	}

	return model, nil
}

type builder struct {
	model       *types.Model
	label       string
	zoneAssetID map[string]string // OTM trustZone id -> Threagile trust boundary id
	compAssetID map[string]string // OTM component id -> Threagile technical asset id
	usedIDs     map[string]bool   // guards against toID normalisation collisions
	mapping     *mapping.Ruleset  // optional user-supplied mapping dictionary (P3)
}

// uniqueID returns base, or base-2/base-3/… if base is already taken, so two
// elements whose IDs normalise identically don't overwrite each other.
func (b *builder) uniqueID(base string) string {
	if b.usedIDs == nil {
		b.usedIDs = map[string]bool{}
	}
	id := base
	for n := 2; b.usedIDs[id]; n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	b.usedIDs[id] = true
	return id
}

func (b *builder) buildTrustBoundary(z otmZone) {
	if strings.TrimSpace(z.Id) == "" {
		return
	}
	title := z.Name
	if strings.TrimSpace(title) == "" {
		title = z.Id
	}
	id := b.uniqueID(toID("zone", z.Id, b.label))
	boundaryType := types.NetworkVirtualLAN
	lower := strings.ToLower(title + " " + z.Description)
	if strings.Contains(lower, "internet") || strings.Contains(lower, "untrusted") || strings.Contains(lower, "public") {
		boundaryType = types.NetworkOnPrem
	}
	// A low trustRating (untrusted zone, e.g. public internet) is also a
	// deterministic signal independent of naming.
	if z.Risk.TrustRating != nil && *z.Risk.TrustRating < 30 {
		boundaryType = types.NetworkOnPrem
	}
	b.model.TrustBoundaries[id] = &types.TrustBoundary{
		Id:          id,
		Title:       title,
		Description: z.Description,
		Type:        boundaryType,
		Tags:        []string{reviewTag},
	}
	b.zoneAssetID[z.Id] = id
}

// nestTrustBoundaries wires each zone's parent.trustZone reference onto the
// parent's TrustBoundariesNested list.
func (b *builder) nestTrustBoundaries(zones []otmZone) {
	for _, z := range zones {
		if z.Parent == nil || strings.TrimSpace(z.Parent.TrustZone) == "" {
			continue
		}
		childID, ok := b.zoneAssetID[z.Id]
		if !ok {
			continue
		}
		parentID, ok := b.zoneAssetID[z.Parent.TrustZone]
		if !ok || parentID == childID {
			continue
		}
		parent := b.model.TrustBoundaries[parentID]
		parent.TrustBoundariesNested = append(parent.TrustBoundariesNested, childID)
	}
	for _, tb := range b.model.TrustBoundaries {
		sort.Strings(tb.TrustBoundariesNested)
	}
}

func (b *builder) buildTechnicalAsset(c otmComp) {
	if strings.TrimSpace(c.Id) == "" {
		return
	}
	title := c.Name
	if strings.TrimSpace(title) == "" {
		title = c.Id
	}
	id := b.uniqueID(toID("comp", c.Id, b.label))
	assetType, tech := classifyComponent(c.Type)

	tags := append([]string{reviewTag}, c.Tags...)
	asset := &types.TechnicalAsset{
		Id:              id,
		Title:           title,
		Description:     c.Description,
		Type:            assetType,
		Technologies:    types.TechnologyList{&types.Technology{Name: tech}},
		Machine:         types.Virtual,
		Internet:        assetType == types.ExternalEntity,
		Encryption:      types.NoneEncryption,
		Confidentiality: types.Confidential,
		Integrity:       types.Critical,
		Availability:    types.Critical,
		Tags:            tags,
	}
	if assetType == types.ExternalEntity {
		asset.UsedAsClientByHuman = true
	}
	mapping.ApplyToTechnicalAsset(b.mapping, asset, mapping.Element{Label: title})
	b.model.TechnicalAssets[id] = asset
	b.compAssetID[c.Id] = id
}

// assignComponentsToZones places each component inside the trust boundary
// named by its parent.trustZone reference.
func (b *builder) assignComponentsToZones(comps []otmComp) {
	inside := map[string][]string{}
	for _, c := range comps {
		if c.Parent == nil || strings.TrimSpace(c.Parent.TrustZone) == "" {
			continue
		}
		assetID, ok := b.compAssetID[c.Id]
		if !ok {
			continue
		}
		zoneID, ok := b.zoneAssetID[c.Parent.TrustZone]
		if !ok {
			continue
		}
		inside[zoneID] = append(inside[zoneID], assetID)
	}
	for zoneID, ids := range inside {
		sort.Strings(ids)
		b.model.TrustBoundaries[zoneID].TechnicalAssetsInside = ids
	}

	// A component whose internet-boundary is untrusted (network-on-prem
	// classification from name/rating heuristics above) is internet-facing.
	for _, c := range comps {
		if c.Parent == nil {
			continue
		}
		zoneID, ok := b.zoneAssetID[c.Parent.TrustZone]
		if !ok {
			continue
		}
		assetID, ok := b.compAssetID[c.Id]
		if !ok {
			continue
		}
		zone := b.model.TrustBoundaries[zoneID]
		if zone.Type == types.NetworkOnPrem {
			b.model.TechnicalAssets[assetID].Internet = true
		}
	}
}

func (b *builder) buildCommunicationLink(f otmFlow) {
	srcID, okS := b.compAssetID[f.Source]
	dstID, okT := b.compAssetID[f.Destination]
	if !okS || !okT || srcID == dstID {
		return
	}
	title := f.Name
	if strings.TrimSpace(title) == "" {
		title = f.Source + " → " + f.Destination
	}
	linkID := b.uniqueID(toID("flow", f.Id, f.Source, f.Destination, b.label))
	link := &types.CommunicationLink{
		Id:             linkID,
		SourceId:       srcID,
		TargetId:       dstID,
		Title:          title,
		Description:    f.Description,
		Protocol:       types.HTTPS,
		Authentication: types.NoneAuthentication,
		Authorization:  types.NoneAuthorization,
		Usage:          types.Business,
		Tags:           append([]string{reviewTag}, f.Tags...),
	}
	mapping.ApplyToCommunicationLink(b.mapping, link, mapping.Element{Label: title, Edge: true})
	b.model.CommunicationLinks[linkID] = link
	srcAsset := b.model.TechnicalAssets[srcID]
	srcAsset.CommunicationLinks = append(srcAsset.CommunicationLinks, link)

	if f.Bidirectional {
		backID := b.uniqueID(toID("flow", f.Id, f.Destination, f.Source, b.label))
		back := &types.CommunicationLink{
			Id:             backID,
			SourceId:       dstID,
			TargetId:       srcID,
			Title:          title + " (reverse)",
			Description:    f.Description,
			Protocol:       types.HTTPS,
			Authentication: types.NoneAuthentication,
			Authorization:  types.NoneAuthorization,
			Usage:          types.Business,
			Tags:           append([]string{reviewTag}, f.Tags...),
		}
		mapping.ApplyToCommunicationLink(b.mapping, back, mapping.Element{Label: back.Title, Edge: true})
		b.model.CommunicationLinks[backID] = back
		dstAsset := b.model.TechnicalAssets[dstID]
		dstAsset.CommunicationLinks = append(dstAsset.CommunicationLinks, back)
	}
}

func (b *builder) buildDataAsset(a otmAsset) {
	if strings.TrimSpace(a.Id) == "" {
		return
	}
	title := a.Name
	if strings.TrimSpace(title) == "" {
		title = a.Id
	}
	id := b.uniqueID(toID("asset", a.Id, b.label))
	da := &types.DataAsset{
		Id:              id,
		Title:           title,
		Description:     a.Description,
		Tags:            append([]string{reviewTag}, a.Tags...),
		Confidentiality: confidentialityFromScore(a.Risk.Confidentiality),
		Integrity:       criticalityFromScore(a.Risk.Integrity),
		Availability:    criticalityFromScore(a.Risk.Availability),
	}
	mapping.ApplyToDataAsset(b.mapping, da, mapping.Element{Label: title})
	b.model.DataAssets[id] = da
}
