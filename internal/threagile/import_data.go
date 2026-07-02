package threagile

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	composeimport "github.com/threagile/threagile/pkg/import/compose"
	drawioimport "github.com/threagile/threagile/pkg/import/drawio"
	k8simport "github.com/threagile/threagile/pkg/import/kubernetes"
	"github.com/threagile/threagile/pkg/import/mapping"
	oaimport "github.com/threagile/threagile/pkg/import/openapi"
	otmimport "github.com/threagile/threagile/pkg/import/otm"
	tfimport "github.com/threagile/threagile/pkg/import/terraform"
	tdimport "github.com/threagile/threagile/pkg/import/threatdragon"
	"github.com/threagile/threagile/pkg/types"
)

// initImportData registers the `import` parent command with terraform and openapi subcommands.
// It is separate from the existing import.go which handles the upstream `import-model` command.
func (what *Threagile) initImportData() *Threagile {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import architecture data from external sources into a Threagile model",
		Long: `Import architecture data from external tools and generate or update a Threagile
threat model YAML file.

Supported sources:
  terraform  Parse 'terraform show -json' output
  openapi    Parse an OpenAPI 3.x specification
  kubernetes Parse Kubernetes manifests (multi-document YAML)
  compose    Parse a docker-compose file
  threat-dragon Parse an OWASP Threat Dragon (v2) diagram model
  drawio     Parse a draw.io / diagrams.net diagram (mxGraph XML; best-effort)
  otm        Parse an Open Threat Model (OTM) JSON document

By default the generated model fragment is written to stdout. Use --output to
write it to a file, or --diff to preview a summary without writing.`,
	}

	importCmd.AddCommand(what.newImportTerraformCmd())
	importCmd.AddCommand(what.newImportOpenAPICmd())
	importCmd.AddCommand(what.newImportKubernetesCmd())
	importCmd.AddCommand(what.newImportComposeCmd())
	importCmd.AddCommand(what.newImportThreatDragonCmd())
	importCmd.AddCommand(what.newImportDrawioCmd())
	importCmd.AddCommand(what.newImportOTMCmd())

	what.rootCmd.AddCommand(importCmd)
	return what
}

func (what *Threagile) newImportTerraformCmd() *cobra.Command {
	var planFile string
	var outputFile string
	var label string
	var diff bool

	cmd := &cobra.Command{
		Use:   "terraform",
		Short: "Import Terraform IaC into a Threagile model fragment",
		Long: `Parse the JSON output of 'terraform show -json' and produce a Threagile
model fragment containing technical assets, trust boundaries and stub data
assets for every recognised Terraform resource.

Example:
  terraform show -json terraform.tfstate > plan.json
  threagile import terraform --plan plan.json --output model-fragment.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			data, err := readInput(planFile)
			if err != nil {
				return fmt.Errorf("terraform import: %w", err)
			}

			opts := tfimport.ImportOptions{SourceLabel: label}
			model, err := tfimport.Import(data, opts)
			if err != nil {
				return err
			}

			return writeOrDiff(cmd, model, outputFile, diff)
		},
	}

	cmd.Flags().StringVar(&planFile, "plan", "", "Path to 'terraform show -json' output file (default: stdin)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Write model YAML to this file (default: stdout)")
	cmd.Flags().StringVar(&label, "label", "tf", "Short label appended to generated asset IDs (e.g. 'prod')")
	cmd.Flags().BoolVar(&diff, "diff", false, "Show what would be added without writing output")

	return cmd
}

func (what *Threagile) newImportOpenAPICmd() *cobra.Command {
	var specFile string
	var outputFile string
	var label string
	var diff bool

	cmd := &cobra.Command{
		Use:   "openapi",
		Short: "Import an OpenAPI 3.x spec into a Threagile model fragment",
		Long: `Parse an OpenAPI 3.x specification (YAML or JSON) and produce a Threagile
model fragment containing web-service-rest technical assets, communication
links, and data assets with PII heuristics applied to schema properties.

Example:
  threagile import openapi --spec api.yaml --output model-fragment.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			data, err := readInput(specFile)
			if err != nil {
				return fmt.Errorf("openapi import: %w", err)
			}

			opts := oaimport.ImportOptions{SourceLabel: label}
			model, err := oaimport.Import(data, opts)
			if err != nil {
				return err
			}

			return writeOrDiff(cmd, model, outputFile, diff)
		},
	}

	cmd.Flags().StringVar(&specFile, "spec", "", "Path to OpenAPI 3.x spec file (default: stdin)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Write model YAML to this file (default: stdout)")
	cmd.Flags().StringVar(&label, "label", "api", "Short label appended to generated asset IDs")
	cmd.Flags().BoolVar(&diff, "diff", false, "Show a summary of what would be generated without writing output")

	return cmd
}

func (what *Threagile) newImportKubernetesCmd() *cobra.Command {
	var manifestFile string
	var outputFile string
	var label string
	var diff bool

	cmd := &cobra.Command{
		Use:   "kubernetes",
		Short: "Import Kubernetes manifests into a Threagile model fragment",
		Long: `Parse Kubernetes manifests (a single file or a multi-document YAML stream)
and produce a Threagile model fragment. Workloads (Deployment/StatefulSet/
DaemonSet/Pod/Job/CronJob) become technical assets (datastores detected from
container images), namespaces become trust boundaries, Services/Ingresses set
internet exposure and communication links, and Secrets/PVCs become data assets.

Example:
  kubectl get all,ingress,secret -A -o yaml > manifests.yaml
  threagile import kubernetes --manifests manifests.yaml --output model-fragment.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			data, err := readInput(manifestFile)
			if err != nil {
				return fmt.Errorf("kubernetes import: %w", err)
			}

			opts := k8simport.ImportOptions{SourceLabel: label}
			model, err := k8simport.Import(data, opts)
			if err != nil {
				return err
			}

			return writeOrDiff(cmd, model, outputFile, diff)
		},
	}

	cmd.Flags().StringVar(&manifestFile, "manifests", "", "Path to Kubernetes manifest YAML file (default: stdin)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Write model YAML to this file (default: stdout)")
	cmd.Flags().StringVar(&label, "label", "k8s", "Short label appended to generated asset IDs (e.g. 'prod')")
	cmd.Flags().BoolVar(&diff, "diff", false, "Show a summary of what would be generated without writing output")

	return cmd
}

func (what *Threagile) newImportComposeCmd() *cobra.Command {
	var composeFile string
	var outputFile string
	var label string
	var diff bool

	cmd := &cobra.Command{
		Use:   "compose",
		Short: "Import a docker-compose file into a Threagile model fragment",
		Long: `Parse a docker-compose file and produce a Threagile model fragment. Services
become technical assets (datastores detected from the image), host-published
ports set internet exposure, depends_on becomes communication links, networks
become trust boundaries (internal networks are treated as more isolated), and
secret-looking environment variables produce an application-secrets data asset.

Example:
  threagile import compose --compose docker-compose.yml --output model-fragment.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			data, err := readInput(composeFile)
			if err != nil {
				return fmt.Errorf("compose import: %w", err)
			}

			opts := composeimport.ImportOptions{SourceLabel: label}
			model, err := composeimport.Import(data, opts)
			if err != nil {
				return err
			}

			return writeOrDiff(cmd, model, outputFile, diff)
		},
	}

	cmd.Flags().StringVar(&composeFile, "compose", "", "Path to docker-compose file (default: stdin)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Write model YAML to this file (default: stdout)")
	cmd.Flags().StringVar(&label, "label", "compose", "Short label appended to generated asset IDs (e.g. 'prod')")
	cmd.Flags().BoolVar(&diff, "diff", false, "Show a summary of what would be generated without writing output")

	return cmd
}

func (what *Threagile) newImportThreatDragonCmd() *cobra.Command {
	var modelFile string
	var outputFile string
	var label string
	var diff bool
	var scaffold bool
	var mappingFile string
	var stubDataAssetsFlag bool

	cmd := &cobra.Command{
		Use:   "threat-dragon",
		Short: "Import an OWASP Threat Dragon diagram into a Threagile model fragment",
		Long: `Parse an OWASP Threat Dragon (v2) model file and produce a Threagile model
fragment — a fully deterministic diagram-to-YAML conversion (no AI). Actors
become external entities, processes/stores become technical assets (datastores
classified from the node name), data flows become communication links, and
trust-boundary boxes become trust boundaries (membership resolved by diagram
geometry).

Example:
  threagile import threat-dragon --tdmodel model.json --output model-fragment.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			data, err := readInput(modelFile)
			if err != nil {
				return fmt.Errorf("threat-dragon import: %w", err)
			}

			ruleset, err := loadMapping(mappingFile)
			if err != nil {
				return err
			}

			opts := tdimport.ImportOptions{SourceLabel: label, Mapping: ruleset}
			model, err := tdimport.Import(data, opts)
			if err != nil {
				return err
			}
			if stubDataAssetsFlag {
				stubDataAssets(model, "threat-dragon")
			}

			return writeScaffoldedOrDiff(cmd, model, outputFile, diff, scaffold, "threat-dragon", modelFile)
		},
	}

	cmd.Flags().StringVar(&modelFile, "tdmodel", "", "Path to the Threat Dragon JSON model file (default: stdin)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Write model YAML to this file (default: stdout)")
	cmd.Flags().StringVar(&label, "label", "td", "Short label appended to generated asset IDs")
	cmd.Flags().BoolVar(&diff, "diff", false, "Show a summary of what would be generated without writing output")
	cmd.Flags().BoolVar(&scaffold, "scaffold", true, "Annotate the output with TODO(review) comments on every inferred field (set false for plain output)")
	cmd.Flags().StringVar(&mappingFile, "mapping", "", "Path to a mapping dictionary YAML file (see docs) to correct/override importer heuristics")
	cmd.Flags().BoolVar(&stubDataAssetsFlag, "stub-data-assets", true, "Generate stub data assets for datastores and internet-inbound links so the model produces meaningful risks")

	return cmd
}

func (what *Threagile) newImportDrawioCmd() *cobra.Command {
	var diagramFile string
	var outputFile string
	var label string
	var diff bool
	var scaffold bool
	var mappingFile string
	var stubDataAssetsFlag bool

	cmd := &cobra.Command{
		Use:   "drawio",
		Short: "Import a draw.io / diagrams.net diagram into a Threagile model fragment (best-effort)",
		Long: `Parse a draw.io / diagrams.net (mxGraph) diagram and produce a Threagile model
fragment. draw.io is a GENERIC diagram format with no built-in threat-model
semantics, so this conversion is deterministic but LOSSY: shapes are classified
by style and label (cylinders/named stores -> datastores, actor shapes/named
users -> external entities, the rest -> processes), edges -> communication links,
and boundary-styled/named rectangles -> trust boundaries (membership by
geometry). Every generated asset is tagged "review-drawio" — review the fragment
before merging. There is no AI involved.

If your .drawio file is compressed, re-export it as uncompressed XML
(Extras -> Edit Diagram, or File -> Export as -> XML, uncompressed).

Example:
  threagile import drawio --diagram model.drawio --output model-fragment.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			data, err := readInput(diagramFile)
			if err != nil {
				return fmt.Errorf("drawio import: %w", err)
			}

			ruleset, err := loadMapping(mappingFile)
			if err != nil {
				return err
			}

			opts := drawioimport.ImportOptions{SourceLabel: label, Mapping: ruleset}
			model, err := drawioimport.Import(data, opts)
			if err != nil {
				return err
			}
			if stubDataAssetsFlag {
				stubDataAssets(model, "drawio")
			}

			return writeScaffoldedOrDiff(cmd, model, outputFile, diff, scaffold, "drawio", diagramFile)
		},
	}

	cmd.Flags().StringVar(&diagramFile, "diagram", "", "Path to the draw.io diagram file (default: stdin)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Write model YAML to this file (default: stdout)")
	cmd.Flags().StringVar(&label, "label", "drawio", "Short label appended to generated asset IDs")
	cmd.Flags().BoolVar(&diff, "diff", false, "Show a summary of what would be generated without writing output")
	cmd.Flags().BoolVar(&scaffold, "scaffold", true, "Annotate the output with TODO(review) comments on every inferred field (set false for plain output)")
	cmd.Flags().StringVar(&mappingFile, "mapping", "", "Path to a mapping dictionary YAML file (see docs) to correct/override importer heuristics")
	cmd.Flags().BoolVar(&stubDataAssetsFlag, "stub-data-assets", true, "Generate stub data assets for datastores and internet-inbound links so the model produces meaningful risks")

	return cmd
}

func (what *Threagile) newImportOTMCmd() *cobra.Command {
	var modelFile string
	var outputFile string
	var label string
	var diff bool
	var scaffold bool
	var mappingFile string
	var stubDataAssetsFlag bool

	cmd := &cobra.Command{
		Use:   "otm",
		Short: "Import an Open Threat Model (OTM) document into a Threagile model fragment",
		Long: `Parse an Open Threat Model (OTM) JSON document — the IriusRisk-led open
interchange format — and produce a Threagile model fragment. This is a fully
deterministic, near-lossless conversion (no AI): trust zones become trust
boundaries (nested via each zone's parent.trustZone reference), components
become technical assets (classified by their OTM "type" field), dataflows
become communication links, and OTM assets (which, unlike pure diagrams,
actually carry data) become data assets. Every generated element is tagged
"review-otm" — review the fragment before merging.

Example:
  threagile import otm --file model.otm.json --output model-fragment.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			data, err := readInput(modelFile)
			if err != nil {
				return fmt.Errorf("otm import: %w", err)
			}

			ruleset, err := loadMapping(mappingFile)
			if err != nil {
				return err
			}

			opts := otmimport.ImportOptions{SourceLabel: label, Mapping: ruleset}
			model, err := otmimport.Import(data, opts)
			if err != nil {
				return err
			}
			if stubDataAssetsFlag {
				stubDataAssets(model, "otm")
			}

			return writeScaffoldedOrDiff(cmd, model, outputFile, diff, scaffold, "otm", modelFile)
		},
	}

	cmd.Flags().StringVar(&modelFile, "file", "", "Path to the OTM JSON model file (default: stdin)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Write model YAML to this file (default: stdout)")
	cmd.Flags().StringVar(&label, "label", "otm", "Short label appended to generated asset IDs")
	cmd.Flags().BoolVar(&diff, "diff", false, "Show a summary of what would be generated without writing output")
	cmd.Flags().BoolVar(&scaffold, "scaffold", true, "Annotate the output with TODO(review) comments on every inferred field (set false for plain output)")
	cmd.Flags().StringVar(&mappingFile, "mapping", "", "Path to a mapping dictionary YAML file (see docs) to correct/override importer heuristics")
	cmd.Flags().BoolVar(&stubDataAssetsFlag, "stub-data-assets", true, "Generate stub data assets for datastores and internet-inbound links so the model produces meaningful risks")

	return cmd
}

// readInput reads from a file path or stdin if path is empty.
func readInput(path string) ([]byte, error) {
	if path == "" {
		return os.ReadFile("/dev/stdin")
	}
	return os.ReadFile(path)
}

// loadMapping loads a P3 mapping dictionary from path, or returns a nil
// (no-op) *mapping.Ruleset when path is empty — every importer/apply
// function treats nil as "no rules configured".
func loadMapping(path string) (*mapping.Ruleset, error) {
	if path == "" {
		return nil, nil
	}
	ruleset, err := mapping.Load(path)
	if err != nil {
		return nil, err
	}
	return ruleset, nil
}

// writeOrDiff either writes the model as YAML (to file or stdout) or prints a diff summary.
func writeOrDiff(cmd *cobra.Command, model *types.Model, outputFile string, diff bool) error {
	if diff {
		printModelSummary(cmd, model)
		return nil
	}

	// Convert to the authoring (input) format so the emitted YAML is directly
	// parseable/analyzable; marshalling a raw types.Model produces YAML that the
	// model parser cannot read back.
	out, err := yaml.Marshal(modelToInput(model))
	if err != nil {
		return fmt.Errorf("failed to marshal model to YAML: %w", err)
	}

	if outputFile == "" {
		cmd.Print(string(out))
		return nil
	}

	if err := os.WriteFile(outputFile, out, 0o600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	cmd.Printf("Written %d bytes to %s\n", len(out), outputFile)
	return nil
}

// writeScaffoldedOrDiff is writeOrDiff's counterpart for diagram-derived
// importers (drawio, threat-dragon, otm). When scaffold is true it emits the
// annotated "scaffold" YAML (see import_scaffold.go): TODO(review)
// head-comments on every importer-guessed field plus a file-header summary.
// When scaffold is false it falls back to the exact plain output writeOrDiff
// produces, so --scaffold=false stays a genuine escape hatch.
func writeScaffoldedOrDiff(cmd *cobra.Command, model *types.Model, outputFile string, diff bool, scaffold bool, importerName, sourceFile string) error {
	if diff {
		printModelSummary(cmd, model)
		return nil
	}

	var out []byte
	var err error
	if scaffold {
		out, err = buildScaffoldYAML(model, importerName, sourceFile)
	} else {
		out, err = yaml.Marshal(modelToInput(model))
	}
	if err != nil {
		return fmt.Errorf("failed to marshal model to YAML: %w", err)
	}

	if outputFile == "" {
		cmd.Print(string(out))
		return nil
	}

	if err := os.WriteFile(outputFile, out, 0o600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	cmd.Printf("Written %d bytes to %s\n", len(out), outputFile)
	return nil
}

// printModelSummary prints a human-readable summary of the generated model
// fragment. Every section is sorted so the output is deterministic (stable CI
// snapshots / review diffs), unlike raw map iteration.
func printModelSummary(cmd *cobra.Command, model *types.Model) {
	cmd.Printf("Model fragment summary: %s\n", model.Title)
	cmd.Printf("  Technical assets (%d):\n", len(model.TechnicalAssets))
	for _, id := range sortedMapKeys(model.TechnicalAssets) {
		a := model.TechnicalAssets[id]
		techNames := make([]string, 0, len(a.Technologies))
		for _, t := range a.Technologies {
			techNames = append(techNames, t.Name)
		}
		cmd.Printf("    %-40s  type=%-10s  tech=%s\n", id, a.Type, strings.Join(techNames, ","))
	}
	cmd.Printf("  Trust boundaries (%d):\n", len(model.TrustBoundaries))
	for _, id := range sortedMapKeys(model.TrustBoundaries) {
		cmd.Printf("    %-40s  type=%s\n", id, model.TrustBoundaries[id].Type)
	}
	cmd.Printf("  Data assets (%d):\n", len(model.DataAssets))
	for _, id := range sortedMapKeys(model.DataAssets) {
		pii := ""
		if model.DataAssets[id].HasPii {
			pii = " [PII]"
		}
		cmd.Printf("    %-40s%s\n", id, pii)
	}
	cmd.Printf("  Communication links (%d):\n", len(model.CommunicationLinks))
	for _, id := range sortedMapKeys(model.CommunicationLinks) {
		cmd.Printf("    %s\n", id)
	}
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
