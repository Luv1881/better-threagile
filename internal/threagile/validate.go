package threagile

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/secretscan"
	"github.com/threagile/threagile/pkg/source"
)

// ValidateReport is the machine-readable result of `validate --json`.
type ValidateReport struct {
	Model   string           `json:"model"`
	Valid   bool             `json:"valid"`
	Errors  []string         `json:"errors"`
	Secrets []ValidateSecret `json:"secrets,omitempty"`
}

type ValidateSecret struct {
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Preview string `json:"preview"`
}

func (what *Threagile) initValidate() *Threagile {
	var failOnSecrets bool
	var jsonOutput bool
	validate := &cobra.Command{
		Use:     ValidateCommand,
		Short:   "Parse and validate the model YAML without running risk rules",
		Aliases: []string{"check"},
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			modelFile := what.config.GetInputFile()

			errs := validateModel(modelFile)
			// Secrets do not belong in a model file. Surface any that slipped in
			// (redacted), and optionally fail the build.
			secrets := scanModelForSecrets(modelFile)

			if jsonOutput {
				report := ValidateReport{Model: modelFile, Valid: len(errs) == 0, Errors: errs}
				for _, s := range secrets {
					report.Secrets = append(report.Secrets, ValidateSecret{Line: s.Line, Rule: s.Rule, Preview: s.Preview})
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return err
				}
			} else {
				cmd.Printf("Validating model: %s\n", modelFile)
				for _, s := range secrets {
					cmd.Printf("⚠ possible secret at line %d (%s): %s\n", s.Line, s.Rule, s.Preview)
				}
				if len(errs) == 0 {
					cmd.Println("✓ Model is valid")
				} else {
					cmd.Printf("✗ Found %d validation error(s):\n\n", len(errs))
					for i, e := range errs {
						cmd.Printf("  %d. %s\n", i+1, e)
					}
				}
			}

			if len(errs) > 0 {
				return fmt.Errorf("model validation failed with %d error(s)", len(errs))
			}
			if failOnSecrets && len(secrets) > 0 {
				return &exitCodeError{code: 3, msg: fmt.Sprintf("found %d possible secret(s) in the model file", len(secrets))}
			}
			return nil
		},
	}
	validate.Flags().BoolVar(&failOnSecrets, "fail-on-secrets", false, "exit 3 if a possible secret is found in the model file")
	validate.Flags().BoolVar(&jsonOutput, "json", false, "output the validation result as JSON")

	what.rootCmd.AddCommand(validate)
	return what
}

// scanModelForSecrets reads the raw model file and scans it for credentials.
// A read error is non-fatal here (validateModel already reports load failures).
func scanModelForSecrets(modelFile string) []secretscan.Finding {
	data, err := os.ReadFile(modelFile) // #nosec G304 -- operator-supplied model path
	if err != nil {
		return nil
	}
	return secretscan.Scan(data)
}

// validateModel loads and parses the model, returning human-readable error strings.
func validateModel(modelFile string) []string {
	var errs []string

	modelInput := new(input.Model).Defaults()
	if err := modelInput.Load(modelFile); err != nil {
		return []string{fmt.Sprintf("failed to load model: %v", err)}
	}

	// Source line of each named entity (best-effort), so errors can point at the
	// offending element. Empty/absent => no suffix (graceful degradation).
	entityLines := source.EntityLines(modelFile)
	loc := func(title string) string {
		if l, ok := entityLines[title]; ok {
			return fmt.Sprintf(" (%s)", l.String())
		}
		return ""
	}

	// Check for dangling data asset references in technical assets
	knownDataAssets := make(map[string]bool)
	for _, da := range modelInput.DataAssets {
		knownDataAssets[da.ID] = true
	}

	knownTechAssets := make(map[string]bool)
	for _, ta := range modelInput.TechnicalAssets {
		knownTechAssets[ta.ID] = true
	}

	for taTitle, ta := range modelInput.TechnicalAssets {
		for _, ref := range ta.DataAssetsProcessed {
			if !knownDataAssets[ref] {
				errs = append(errs, fmt.Sprintf("technical asset %q references unknown data asset %q in data_assets_processed%s", taTitle, ref, loc(taTitle)))
			}
		}
		for _, ref := range ta.DataAssetsStored {
			if !knownDataAssets[ref] {
				errs = append(errs, fmt.Sprintf("technical asset %q references unknown data asset %q in data_assets_stored%s", taTitle, ref, loc(taTitle)))
			}
		}
		for linkTitle, link := range ta.CommunicationLinks {
			if link.Target != "" && !knownTechAssets[link.Target] {
				errs = append(errs, fmt.Sprintf("communication link %q of %q references unknown target asset %q%s", linkTitle, taTitle, link.Target, loc(taTitle)))
			}
			for _, ref := range link.DataAssetsSent {
				if !knownDataAssets[ref] {
					errs = append(errs, fmt.Sprintf("communication link %q of %q references unknown data asset %q in data_assets_sent%s", linkTitle, taTitle, ref, loc(taTitle)))
				}
			}
			for _, ref := range link.DataAssetsReceived {
				if !knownDataAssets[ref] {
					errs = append(errs, fmt.Sprintf("communication link %q of %q references unknown data asset %q in data_assets_received%s", linkTitle, taTitle, ref, loc(taTitle)))
				}
			}
		}
	}

	// Check trust boundary asset references
	for tbTitle, tb := range modelInput.TrustBoundaries {
		for _, ref := range tb.TechnicalAssetsInside {
			if !knownTechAssets[ref] {
				errs = append(errs, fmt.Sprintf("trust boundary %q references unknown technical asset %q%s", tbTitle, ref, loc(tbTitle)))
			}
		}
	}

	// Check shared runtime asset references
	for srTitle, sr := range modelInput.SharedRuntimes {
		for _, ref := range sr.TechnicalAssetsRunning {
			if !knownTechAssets[ref] {
				errs = append(errs, fmt.Sprintf("shared runtime %q references unknown technical asset %q%s", srTitle, ref, loc(srTitle)))
			}
		}
	}

	// Check PASTA threat scenario entry asset references
	for title, ts := range modelInput.ThreatScenarios {
		for _, ref := range ts.EntryAssets {
			if !knownTechAssets[ref] {
				errs = append(errs, fmt.Sprintf("threat scenario %q references unknown entry asset %q%s", title, ref, loc(title)))
			}
		}
	}

	// Check VAST business process asset references
	for title, bp := range modelInput.BusinessProcesses {
		for _, ref := range bp.SupportedByTechnicalAssets {
			if !knownTechAssets[ref] {
				errs = append(errs, fmt.Sprintf("business process %q references unknown technical asset %q%s", title, ref, loc(title)))
			}
		}
	}

	// Check for duplicate IDs
	seenIDs := make(map[string]string)
	checkDup := func(id, kind string) {
		if id == "" {
			return
		}
		if prev, dup := seenIDs[id]; dup {
			errs = append(errs, fmt.Sprintf("duplicate ID %q used by both %s and %s", id, prev, kind))
		} else {
			seenIDs[id] = kind
		}
	}
	for _, da := range modelInput.DataAssets {
		checkDup(da.ID, "data asset")
	}
	for _, ta := range modelInput.TechnicalAssets {
		checkDup(ta.ID, "technical asset")
	}

	// Check tag references
	tagSet := make(map[string]bool)
	for _, t := range modelInput.TagsAvailable {
		tagSet[strings.ToLower(t)] = true
	}
	if len(tagSet) > 0 {
		checkTagRefs := func(tags []string, context, suffix string) {
			for _, tag := range tags {
				if !tagSet[strings.ToLower(tag)] {
					errs = append(errs, fmt.Sprintf("%s uses tag %q that is not in tags_available%s", context, tag, suffix))
				}
			}
		}
		for taTitle, ta := range modelInput.TechnicalAssets {
			checkTagRefs(ta.Tags, fmt.Sprintf("technical asset %q", taTitle), loc(taTitle))
		}
		for daTitle, da := range modelInput.DataAssets {
			checkTagRefs(da.Tags, fmt.Sprintf("data asset %q", daTitle), loc(daTitle))
		}
	}

	// Errors are collected while iterating maps, so sort for deterministic,
	// diffable output (matters for the JSON output and any CI that diffs it).
	sort.Strings(errs)
	return errs
}
