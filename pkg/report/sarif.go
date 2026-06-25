package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

// SARIF 2.1.0 output so risks surface as code-scanning alerts in GitHub/GitLab.
// One rule per risk category, one result per generated risk; results point at
// the model YAML file. Risks whose tracking status is Mitigated, FalsePositive,
// or Accepted are emitted with a suppression so forges hide them by default.

const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription *sarifMessage          `json:"shortDescription,omitempty"`
	FullDescription  *sarifMessage          `json:"fullDescription,omitempty"`
	Help             *sarifMessage          `json:"help,omitempty"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             sarifMessage           `json:"message"`
	Locations           []sarifLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppression     `json:"suppressions,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

func sarifLevel(severity types.RiskSeverity) string {
	switch severity {
	case types.CriticalSeverity, types.HighSeverity:
		return "error"
	case types.ElevatedSeverity, types.MediumSeverity:
		return "warning"
	default:
		return "note"
	}
}

// BuildSarif renders the model's generated risks as a SARIF 2.1.0 log.
// modelFileURI is the (relative) URI results point at; version is the tool version.
func BuildSarif(parsedModel *types.Model, modelFileURI string, version string) ([]byte, error) {
	categoryIDs := make([]string, 0, len(parsedModel.GeneratedRisksByCategory))
	for categoryID := range parsedModel.GeneratedRisksByCategory {
		categoryIDs = append(categoryIDs, categoryID)
	}
	sort.Strings(categoryIDs)

	rules := make([]sarifRule, 0, len(categoryIDs))
	ruleIndexByID := make(map[string]int, len(categoryIDs))
	for _, categoryID := range categoryIDs {
		rule := sarifRule{ID: categoryID}
		if category := parsedModel.GetRiskCategory(categoryID); category != nil {
			rule.Name = category.Title
			if category.Description != "" {
				rule.ShortDescription = &sarifMessage{Text: category.Description}
			}
			fullText := category.Impact
			if category.Mitigation != "" {
				fullText += "\n\nMitigation: " + category.Mitigation
			}
			if fullText != "" {
				rule.FullDescription = &sarifMessage{Text: fullText}
			}
			// The SARIF help panel is what a developer reads in their IDE / GitHub
			// code-scanning to fix the finding, so lead with the actionable
			// remediation (action + mitigation) before the detection logic.
			var help string
			if category.Action != "" {
				help += "How to fix: " + category.Action + "\n\n"
			}
			if category.Mitigation != "" {
				help += "Mitigation: " + category.Mitigation + "\n\n"
			}
			if category.Check != "" {
				help += "Check: " + category.Check
			}
			if help != "" {
				rule.Help = &sarifMessage{Text: strings.TrimSpace(help)}
			}
			rule.HelpURI = category.CheatSheet
			properties := make(map[string]interface{})
			if category.CWE > 0 {
				properties["cwe"] = fmt.Sprintf("CWE-%d", category.CWE)
			}
			properties["security-severity"] = fmt.Sprintf("%.1f", securitySeverityScore(highestSeverity(parsedModel.GeneratedRisksByCategory[categoryID])))
			properties["stride"] = category.STRIDE.String()
			properties["function"] = category.Function.String()
			rule.Properties = properties
		}
		ruleIndexByID[categoryID] = len(rules)
		rules = append(rules, rule)
	}

	results := make([]sarifResult, 0)
	for _, categoryID := range categoryIDs {
		risks := make([]*types.Risk, len(parsedModel.GeneratedRisksByCategory[categoryID]))
		copy(risks, parsedModel.GeneratedRisksByCategory[categoryID])
		sort.Slice(risks, func(i, j int) bool {
			if risks[i].SyntheticId != risks[j].SyntheticId {
				return risks[i].SyntheticId < risks[j].SyntheticId
			}
			return risks[i].Title < risks[j].Title
		})
		for _, risk := range risks {
			status := risk.RiskStatus
			if tracking, ok := parsedModel.RiskTracking[risk.SyntheticId]; ok {
				status = tracking.Status
			}
			result := sarifResult{
				RuleID:    categoryID,
				RuleIndex: ruleIndexByID[categoryID],
				Level:     sarifLevel(risk.Severity),
				Message:   sarifMessage{Text: stripHTML(risk.Title)},
				Locations: []sarifLocation{
					{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: modelFileURI}}},
				},
				PartialFingerprints: map[string]string{"threagileSyntheticId": risk.SyntheticId},
				Properties: map[string]interface{}{
					"severity":               risk.Severity.String(),
					"exploitationLikelihood": risk.ExploitationLikelihood.String(),
					"exploitationImpact":     risk.ExploitationImpact.String(),
					"dataBreachProbability":  risk.DataBreachProbability.String(),
					"status":                 status.String(),
					"mostRelevantAsset":      risk.MostRelevantTechnicalAssetId,
					"confidence":             risk.Confidence,
				},
			}
			switch status {
			case types.Mitigated, types.FalsePositive, types.Accepted:
				justification := status.String()
				if tracking, ok := parsedModel.RiskTracking[risk.SyntheticId]; ok && tracking.Justification != "" {
					justification = tracking.Justification
				}
				result.Suppressions = []sarifSuppression{{Kind: "external", Justification: justification}}
			}
			results = append(results, result)
		}
	}

	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{Driver: sarifDriver{
					Name:           "Threagile",
					InformationURI: "https://threagile.io",
					Version:        version,
					Rules:          rules,
				}},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(&log, "", "  ")
}

// highestSeverity returns the highest severity among the given risks
// (used as the rule-level security-severity hint).
func highestSeverity(risks []*types.Risk) types.RiskSeverity {
	highest := types.LowSeverity
	for _, risk := range risks {
		if risk.Severity > highest {
			highest = risk.Severity
		}
	}
	return highest
}

// securitySeverityScore maps severity onto the GitHub code-scanning
// security-severity scale (0–10, CVSS-like buckets).
func securitySeverityScore(severity types.RiskSeverity) float64 {
	switch severity {
	case types.CriticalSeverity:
		return 9.5
	case types.HighSeverity:
		return 8.0
	case types.ElevatedSeverity:
		return 6.5
	case types.MediumSeverity:
		return 5.0
	default:
		return 2.0
	}
}

func WriteRisksSARIF(parsedModel *types.Model, modelFileURI string, version string, filename string) error {
	sarifBytes, err := BuildSarif(parsedModel, modelFileURI, version)
	if err != nil {
		return fmt.Errorf("failed to marshal risks to SARIF: %w", err)
	}
	err = os.WriteFile(filename, sarifBytes, 0600)
	if err != nil {
		return fmt.Errorf("failed to write risks to SARIF file: %w", err)
	}
	return nil
}
