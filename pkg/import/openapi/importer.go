// Package openapi converts an OpenAPI 3.x specification into a partial Threagile model.
// The importer creates:
//   - One web-service-rest technical asset per unique tag group (or a single asset for untagged APIs)
//   - Data assets for each unique schema that contains PII field names
//   - A client technical asset representing the browser/app consuming the API
//   - Communication links from the client to the API service
//
// Unknown or ambiguous schemas are labelled for manual review.
//
// Usage:
//
//	result, err := openapi.Import(yamlOrJSONBytes, openapi.ImportOptions{})
package openapi

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/threagile/threagile/pkg/types"
)

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func toID(s string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// ImportOptions controls import behaviour.
type ImportOptions struct {
	// SourceLabel is a short label appended to generated asset IDs. Defaults to "api".
	SourceLabel string
}

// Import parses an OpenAPI 3.x spec (YAML or JSON) and returns a partial *types.Model.
func Import(data []byte, opts ImportOptions) (*types.Model, error) {
	if opts.SourceLabel == "" {
		opts.SourceLabel = "api"
	}

	spec, err := parseSpec(data)
	if err != nil {
		return nil, fmt.Errorf("openapi: failed to parse spec: %w", err)
	}

	model := &types.Model{
		ThreagileVersion: "1.0.0",
		Title:            spec.Info.Title,
		TechnicalAssets:  make(map[string]*types.TechnicalAsset),
		TrustBoundaries:  make(map[string]*types.TrustBoundary),
		DataAssets:       make(map[string]*types.DataAsset),
		TagsAvailable:    []string{},
	}

	// Determine authentication strength from security schemes
	authStrength := detectAuthStrength(spec)

	// Determine if internet-facing from server URLs
	internet := hasInternetServer(spec)

	// Collect all operation tags to group into service assets
	tagGroups := collectTagGroups(spec)

	// Create web-service-rest asset(s)
	apiAssets := buildAPIAssets(spec, tagGroups, opts.SourceLabel, internet, authStrength)
	for _, a := range apiAssets {
		model.TechnicalAssets[a.Id] = a
	}

	// Create a generic browser client asset
	clientID := "client-" + opts.SourceLabel
	clientAsset := &types.TechnicalAsset{
		Id:              clientID,
		Title:           spec.Info.Title + " Client",
		Description:     "API consumer generated from OpenAPI spec",
		Type:            types.ExternalEntity,
		Technologies:    types.TechnologyList{&types.Technology{Name: types.Browser}},
		Internet:        true,
		Confidentiality: types.Public,
		Integrity:       types.Operational,
		Availability:    types.Operational,
	}
	model.TechnicalAssets[clientAsset.Id] = clientAsset

	// Create communication links from client to each API asset
	for _, apiAsset := range apiAssets {
		linkID := "link-" + clientID + "-to-" + apiAsset.Id
		link := &types.CommunicationLink{
			Id:            linkID,
			SourceId:      clientID,
			TargetId:      apiAsset.Id,
			Title:         "API calls",
			Description:   "HTTP/S traffic from client to " + apiAsset.Title,
			Protocol:      types.HTTPS,
			Authentication: authToAuthentication(authStrength),
			Authorization: types.TechnicalUser,
		}
		if model.CommunicationLinks == nil {
			model.CommunicationLinks = make(map[string]*types.CommunicationLink)
		}
		model.CommunicationLinks[linkID] = link

		// Attach link to the client asset
		clientAsset.CommunicationLinks = append(clientAsset.CommunicationLinks, link)
	}

	// Create data assets from schemas
	dataAssets := buildDataAssets(spec, opts.SourceLabel)
	for _, da := range dataAssets {
		model.DataAssets[da.Id] = da
		// Attach PII data assets to all API assets
		for _, apiAsset := range apiAssets {
			apiAsset.DataAssetsProcessed = append(apiAsset.DataAssetsProcessed, da.Id)
		}
	}

	// If no schema-based data assets were found, add a generic stub
	if len(dataAssets) == 0 {
		da := &types.DataAsset{
			Id:              "data-" + opts.SourceLabel,
			Title:           spec.Info.Title + " Data",
			Description:     "API request/response data — review and classify PII fields",
			Confidentiality: types.Confidential,
			Integrity:       types.Critical,
			Availability:    types.Critical,
		}
		model.DataAssets[da.Id] = da
		for _, apiAsset := range apiAssets {
			apiAsset.DataAssetsProcessed = append(apiAsset.DataAssetsProcessed, da.Id)
		}
	}

	return model, nil
}

// parseSpec tries JSON first, then YAML.
func parseSpec(data []byte) (*OpenAPI3, error) {
	var spec OpenAPI3

	// Try JSON
	if json.Unmarshal(data, &spec) == nil && spec.OpenAPI != "" {
		return &spec, nil
	}

	// Try YAML
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// detectAuthStrength returns "mfa", "password", or "" based on security scheme types.
func detectAuthStrength(spec *OpenAPI3) string {
	for _, scheme := range spec.Components.SecuritySchemes {
		switch strings.ToLower(scheme.Type) {
		case "oauth2", "openidconnect":
			return "mfa" // OAuth2/OIDC flows can enforce MFA
		case "http":
			if strings.ToLower(scheme.Scheme) == "bearer" {
				return "password" // Bearer token = at least password-equivalent
			}
			if strings.ToLower(scheme.Scheme) == "basic" {
				return "password"
			}
		case "apikey":
			return "password" // API key = basic secret-based auth
		}
	}
	return "" // no auth detected
}

// hasInternetServer returns true if any server URL looks internet-facing.
func hasInternetServer(spec *OpenAPI3) bool {
	for _, s := range spec.Servers {
		u := strings.ToLower(s.URL)
		if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
			if !strings.Contains(u, "localhost") && !strings.Contains(u, "127.0.0.1") && !strings.Contains(u, "{") {
				return true
			}
		}
	}
	return len(spec.Servers) == 0 // default to true if no server declared (typical for public APIs)
}

// collectTagGroups returns the unique operation tags found in the spec.
// An empty string means untagged operations.
func collectTagGroups(spec *OpenAPI3) []string {
	seen := map[string]bool{}
	for _, path := range spec.Paths {
		for _, op := range path {
			if op == nil {
				continue
			}
			if len(op.Tags) == 0 {
				seen[""] = true
			}
			for _, t := range op.Tags {
				seen[t] = true
			}
		}
	}

	// If only one group, return it directly
	result := make([]string, 0, len(seen))
	for g := range seen {
		result = append(result, g)
	}
	return result
}

// buildAPIAssets creates one web-service-rest technical asset per tag group.
func buildAPIAssets(spec *OpenAPI3, tagGroups []string, label string, internet bool, authStrength string) []*types.TechnicalAsset {
	assets := make([]*types.TechnicalAsset, 0, len(tagGroups))

	for _, tag := range tagGroups {
		var id, title string
		if tag == "" {
			id = "api-service-" + label
			title = spec.Info.Title + " API"
		} else {
			id = "api-" + toID(tag) + "-" + label
			title = spec.Info.Title + " - " + tag
		}

		asset := &types.TechnicalAsset{
			Id:                             id,
			Title:                          title,
			Description:                    spec.Info.Description,
			Type:                           types.Process,
			Technologies:                   types.TechnologyList{&types.Technology{Name: types.WebServiceREST}},
			Internet:                       internet,
			Confidentiality:                types.Confidential,
			Integrity:                      types.Critical,
			Availability:                   types.Critical,
			CustomDevelopedParts:           true,
			RequiresAuthenticationStrength: authStrength,
		}

		if !internet {
			asset.Tags = []string{"internal"}
		}

		assets = append(assets, asset)
	}

	if len(assets) == 0 {
		// Fallback: one generic API asset
		assets = append(assets, &types.TechnicalAsset{
			Id:                   "api-service-" + label,
			Title:                spec.Info.Title + " API",
			Type:                 types.Process,
			Technologies:         types.TechnologyList{&types.Technology{Name: types.WebServiceREST}},
			Internet:             internet,
			Confidentiality:      types.Confidential,
			Integrity:            types.Critical,
			Availability:         types.Critical,
			CustomDevelopedParts: true,
		})
	}

	return assets
}

// buildDataAssets creates data assets for schemas that look like they contain PII.
func buildDataAssets(spec *OpenAPI3, label string) []*types.DataAsset {
	schemas := spec.Components.Schemas
	if schemas == nil {
		schemas = map[string]*OASchema{}
	}

	assets := make([]*types.DataAsset, 0)
	seenPII := map[string]bool{}

	for name, schema := range schemas {
		if schemaContainsPII(schema, schemas, 0) && !seenPII[name] {
			seenPII[name] = true
			da := &types.DataAsset{
				Id:              "data-" + toID(name) + "-" + label,
				Title:           name,
				Description:     fmt.Sprintf("Data from OpenAPI schema %q — PII fields detected by heuristic scan", name),
				Confidentiality: types.Confidential,
				Integrity:       types.Critical,
				Availability:    types.Operational,
				HasPii:          true,
			}
			assets = append(assets, da)
		}
	}

	return assets
}

// authToAuthentication maps an auth strength string to types.Authentication.
func authToAuthentication(strength string) types.Authentication {
	switch strength {
	case "mfa", "hardware":
		return types.ClientCertificate
	case "password":
		return types.Credentials
	default:
		return types.NoneAuthentication
	}
}
