package threagile

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/input"
)

func (what *Threagile) initValidate() *Threagile {
	validate := &cobra.Command{
		Use:     ValidateCommand,
		Short:   "Parse and validate the model YAML without running risk rules",
		Aliases: []string{"check"},
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			modelFile := what.config.GetInputFile()
			cmd.Printf("Validating model: %s\n", modelFile)

			errs := validateModel(modelFile)
			if len(errs) == 0 {
				cmd.Println("✓ Model is valid")
				return nil
			}

			cmd.Printf("✗ Found %d validation error(s):\n\n", len(errs))
			for i, e := range errs {
				cmd.Printf("  %d. %s\n", i+1, e)
			}
			return fmt.Errorf("model validation failed with %d error(s)", len(errs))
		},
	}

	what.rootCmd.AddCommand(validate)
	return what
}

// validateModel loads and parses the model, returning human-readable error strings.
func validateModel(modelFile string) []string {
	var errs []string

	modelInput := new(input.Model).Defaults()
	if err := modelInput.Load(modelFile); err != nil {
		return []string{fmt.Sprintf("failed to load model: %v", err)}
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
				errs = append(errs, fmt.Sprintf("technical asset %q references unknown data asset %q in data_assets_processed", taTitle, ref))
			}
		}
		for _, ref := range ta.DataAssetsStored {
			if !knownDataAssets[ref] {
				errs = append(errs, fmt.Sprintf("technical asset %q references unknown data asset %q in data_assets_stored", taTitle, ref))
			}
		}
		for linkTitle, link := range ta.CommunicationLinks {
			if link.Target != "" && !knownTechAssets[link.Target] {
				errs = append(errs, fmt.Sprintf("communication link %q of %q references unknown target asset %q", linkTitle, taTitle, link.Target))
			}
			for _, ref := range link.DataAssetsSent {
				if !knownDataAssets[ref] {
					errs = append(errs, fmt.Sprintf("communication link %q of %q references unknown data asset %q in data_assets_sent", linkTitle, taTitle, ref))
				}
			}
			for _, ref := range link.DataAssetsReceived {
				if !knownDataAssets[ref] {
					errs = append(errs, fmt.Sprintf("communication link %q of %q references unknown data asset %q in data_assets_received", linkTitle, taTitle, ref))
				}
			}
		}
	}

	// Check trust boundary asset references
	for tbTitle, tb := range modelInput.TrustBoundaries {
		for _, ref := range tb.TechnicalAssetsInside {
			if !knownTechAssets[ref] {
				errs = append(errs, fmt.Sprintf("trust boundary %q references unknown technical asset %q", tbTitle, ref))
			}
		}
	}

	// Check shared runtime asset references
	for srTitle, sr := range modelInput.SharedRuntimes {
		for _, ref := range sr.TechnicalAssetsRunning {
			if !knownTechAssets[ref] {
				errs = append(errs, fmt.Sprintf("shared runtime %q references unknown technical asset %q", srTitle, ref))
			}
		}
	}

	// Check PASTA threat scenario entry asset references
	for title, ts := range modelInput.ThreatScenarios {
		for _, ref := range ts.EntryAssets {
			if !knownTechAssets[ref] {
				errs = append(errs, fmt.Sprintf("threat scenario %q references unknown entry asset %q", title, ref))
			}
		}
	}

	// Check VAST business process asset references
	for title, bp := range modelInput.BusinessProcesses {
		for _, ref := range bp.SupportedByTechnicalAssets {
			if !knownTechAssets[ref] {
				errs = append(errs, fmt.Sprintf("business process %q references unknown technical asset %q", title, ref))
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
		checkTagRefs := func(tags []string, context string) {
			for _, tag := range tags {
				if !tagSet[strings.ToLower(tag)] {
					errs = append(errs, fmt.Sprintf("%s uses tag %q that is not in tags_available", context, tag))
				}
			}
		}
		for taTitle, ta := range modelInput.TechnicalAssets {
			checkTagRefs(ta.Tags, fmt.Sprintf("technical asset %q", taTitle))
		}
		for daTitle, da := range modelInput.DataAssets {
			checkTagRefs(da.Tags, fmt.Sprintf("data asset %q", daTitle))
		}
	}

	return errs
}
