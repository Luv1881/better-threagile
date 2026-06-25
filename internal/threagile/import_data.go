package threagile

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	composeimport "github.com/threagile/threagile/pkg/import/compose"
	k8simport "github.com/threagile/threagile/pkg/import/kubernetes"
	oaimport "github.com/threagile/threagile/pkg/import/openapi"
	tfimport "github.com/threagile/threagile/pkg/import/terraform"
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

By default the generated model fragment is written to stdout. Use --output to
write it to a file, or --diff to preview a summary without writing.`,
	}

	importCmd.AddCommand(what.newImportTerraformCmd())
	importCmd.AddCommand(what.newImportOpenAPICmd())
	importCmd.AddCommand(what.newImportKubernetesCmd())
	importCmd.AddCommand(what.newImportComposeCmd())

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

// readInput reads from a file path or stdin if path is empty.
func readInput(path string) ([]byte, error) {
	if path == "" {
		return os.ReadFile("/dev/stdin")
	}
	return os.ReadFile(path)
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

// printModelSummary prints a human-readable summary of the generated model fragment.
func printModelSummary(cmd *cobra.Command, model *types.Model) {
	cmd.Printf("Model fragment summary: %s\n", model.Title)
	cmd.Printf("  Technical assets (%d):\n", len(model.TechnicalAssets))
	for id, a := range model.TechnicalAssets {
		techNames := make([]string, 0, len(a.Technologies))
		for _, t := range a.Technologies {
			techNames = append(techNames, t.Name)
		}
		cmd.Printf("    %-40s  type=%-10s  tech=%s\n", id, a.Type, strings.Join(techNames, ","))
	}
	cmd.Printf("  Trust boundaries (%d):\n", len(model.TrustBoundaries))
	for id, tb := range model.TrustBoundaries {
		cmd.Printf("    %-40s  type=%s\n", id, tb.Type)
	}
	cmd.Printf("  Data assets (%d):\n", len(model.DataAssets))
	for id, da := range model.DataAssets {
		pii := ""
		if da.HasPii {
			pii = " [PII]"
		}
		cmd.Printf("    %-40s%s\n", id, pii)
	}
	cmd.Printf("  Communication links (%d):\n", len(model.CommunicationLinks))
	for id := range model.CommunicationLinks {
		cmd.Printf("    %s\n", id)
	}
}
