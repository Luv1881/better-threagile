package threagile

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/input"
)

// This file implements `threagile review` (improvement.md P6) — the
// human-in-the-loop step every diagram/IaC importer's "review-<importer>"
// tag (P2 scaffold) and "stub-data-asset" tag (P4 stubs) implies. Clearing a
// finding is intentionally stateless: the user deletes the tag from the
// model YAML. reviewModel/scanReviewTags are also used by `threagile gate`
// (see gate.go) to back the `fail_on_unreviewed` policy rule, so the two
// commands never disagree about what counts as "still needs review".

// reviewTagPattern matches any tag of the form "review-<importer>" (e.g.
// review-drawio, review-mermaid, review-otm, review-threat-dragon).
var reviewTagPattern = regexp.MustCompile(`^review-`)

// ReviewItem is one model element still flagged for manual review.
type ReviewItem struct {
	Kind   string   `json:"kind"` // technical_asset | data_asset | trust_boundary | communication_link
	Name   string   `json:"name"`
	ID     string   `json:"id,omitempty"`
	Parent string   `json:"parent,omitempty"` // owning technical asset title, for communication_link only
	Tags   []string `json:"tags"`             // only the tag(s) that triggered the flag
}

// isReviewTag reports whether tag marks its element for manual review: any
// "review-<importer>" tag, or the P4 stub-data-asset tag.
func isReviewTag(tag string) bool {
	return reviewTagPattern.MatchString(tag) || tag == stubDataAssetTag
}

// matchedTags returns the subset of tags that flag the element for review.
func matchedTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if isReviewTag(t) {
			out = append(out, t)
		}
	}
	return out
}

// reviewModel loads modelFile and returns every element still carrying a
// review-<importer>/stub-data-asset tag, sorted for deterministic output.
func reviewModel(modelFile string) ([]ReviewItem, error) {
	modelInput := new(input.Model).Defaults()
	if err := modelInput.Load(modelFile); err != nil {
		return nil, fmt.Errorf("failed to load model: %w", err)
	}
	return scanReviewTags(modelInput), nil
}

// scanReviewTags walks a parsed model input and collects every
// review-flagged element. Communication links are nested under their owning
// technical asset in the authoring format, so they're scanned alongside it.
func scanReviewTags(modelInput *input.Model) []ReviewItem {
	items := []ReviewItem{}

	for title, ta := range modelInput.TechnicalAssets {
		if tags := matchedTags(ta.Tags); len(tags) > 0 {
			items = append(items, ReviewItem{Kind: "technical_asset", Name: title, ID: ta.ID, Tags: tags})
		}
		for linkTitle, link := range ta.CommunicationLinks {
			if tags := matchedTags(link.Tags); len(tags) > 0 {
				items = append(items, ReviewItem{Kind: "communication_link", Name: linkTitle, Parent: title, Tags: tags})
			}
		}
	}
	for title, da := range modelInput.DataAssets {
		if tags := matchedTags(da.Tags); len(tags) > 0 {
			items = append(items, ReviewItem{Kind: "data_asset", Name: title, ID: da.ID, Tags: tags})
		}
	}
	for title, tb := range modelInput.TrustBoundaries {
		if tags := matchedTags(tb.Tags); len(tags) > 0 {
			items = append(items, ReviewItem{Kind: "trust_boundary", Name: title, ID: tb.ID, Tags: tags})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		if items[i].Parent != items[j].Parent {
			return items[i].Parent < items[j].Parent
		}
		return items[i].Name < items[j].Name
	})
	return items
}

// reviewKindOrder and reviewKindLabel drive the section order/headings of
// the Markdown report.
var reviewKindOrder = []string{"technical_asset", "communication_link", "data_asset", "trust_boundary"}
var reviewKindLabel = map[string]string{
	"technical_asset":    "Technical assets",
	"communication_link": "Communication links",
	"data_asset":         "Data assets",
	"trust_boundary":     "Trust boundaries",
}

// formatReviewMarkdown renders a human-readable review report.
func formatReviewMarkdown(items []ReviewItem) string {
	var sb strings.Builder
	sb.WriteString("# Threagile review\n\n")
	if len(items) == 0 {
		sb.WriteString("No elements are flagged for review — nothing left to confirm.\n")
		return sb.String()
	}
	fmt.Fprintf(&sb, "%d element(s) still carry a `review-<importer>`/`stub-data-asset` tag:\n\n", len(items))

	for _, kind := range reviewKindOrder {
		var rows []ReviewItem
		for _, it := range items {
			if it.Kind == kind {
				rows = append(rows, it)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "## %s (%d)\n\n", reviewKindLabel[kind], len(rows))
		if kind == "communication_link" {
			sb.WriteString("| Link | Technical asset | Tags |\n|------|------------------|------|\n")
			for _, it := range rows {
				fmt.Fprintf(&sb, "| %s | %s | %s |\n", it.Name, it.Parent, strings.Join(it.Tags, ", "))
			}
		} else {
			sb.WriteString("| Name | ID | Tags |\n|------|----|------|\n")
			for _, it := range rows {
				fmt.Fprintf(&sb, "| %s | %s | %s |\n", it.Name, it.ID, strings.Join(it.Tags, ", "))
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func (what *Threagile) initReview() *Threagile {
	var format string
	var failOnUnreviewed bool

	cmd := &cobra.Command{
		Use:   "review",
		Short: "List every model element still flagged for manual review after an import",
		Long: `Scan the model for every technical asset, data asset, trust boundary and
communication link still carrying a "review-<importer>" tag (left by the
diagram/IaC importers — see docs/import-*.md) or a "stub-data-asset" tag (left
by --stub-data-assets). Clearing a finding is stateless: delete the tag from
the model YAML once you've confirmed the field(s) it flags.

review is informational and always exits 0, unless --fail-on-unreviewed is
given, in which case it exits 3 if anything is still flagged — the same
signal the gate policy key "fail_on_unreviewed: true" uses in CI.

Example:
  threagile review --model model-fragment.yaml --format markdown
  threagile review --model model-fragment.yaml --format json
  threagile review --model model-fragment.yaml --fail-on-unreviewed`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			modelFile := what.config.GetInputFile()
			items, err := reviewModel(modelFile)
			if err != nil {
				return fmt.Errorf("review: %w", err)
			}

			switch strings.ToLower(format) {
			case "", "markdown", "md":
				cmd.Print(formatReviewMarkdown(items))
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(items); encErr != nil {
					return encErr
				}
			default:
				return fmt.Errorf("review: unknown --format %q (want markdown or json)", format)
			}

			if failOnUnreviewed && len(items) > 0 {
				return &exitCodeError{code: 3, msg: fmt.Sprintf("review: %d element(s) still flagged for review", len(items))}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "markdown", "output format: markdown or json")
	cmd.Flags().BoolVar(&failOnUnreviewed, "fail-on-unreviewed", false, "exit 3 if any element is still flagged for review")

	what.rootCmd.AddCommand(cmd)
	return what
}
