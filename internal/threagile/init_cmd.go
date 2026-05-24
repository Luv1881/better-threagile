package threagile

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func (what *Threagile) initInit() *Threagile {
	initCmd := &cobra.Command{
		Use:   InitCommand,
		Short: "Interactively scaffold a new threat model",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			outDir := what.config.GetOutputFolder()
			scanner := bufio.NewScanner(os.Stdin)

			ask := func(prompt, defaultVal string) string {
				if defaultVal != "" {
					cmd.Printf("%s [%s]: ", prompt, defaultVal)
				} else {
					cmd.Printf("%s: ", prompt)
				}
				if scanner.Scan() {
					v := strings.TrimSpace(scanner.Text())
					if v == "" {
						return defaultVal
					}
					return v
				}
				return defaultVal
			}

			cmd.Println(Logo)
			cmd.Println("\nWelcome to the Threagile model scaffolder.")
			cmd.Println("Answer the questions below to generate a starter threat model.")
			cmd.Println()

			title := ask("Application title", "My Application")
			authorName := ask("Author name", "Security Team")
			criticality := ask("Business criticality (important/critical/mission-critical)", "important")
			summary := ask("Management summary (one sentence)", "This model covers the "+title+" application.")

			cmd.Println("\nNow let's define your application components.")
			cmd.Println("Enter component names one at a time (empty line to finish):")
			cmd.Println()

			type component struct {
				name     string
				techType string
			}
			var components []component
			for {
				name := ask("Component name (or Enter to finish)", "")
				if name == "" {
					break
				}
				techType := ask(fmt.Sprintf("  Type of %q (web-application/reverse-proxy/web-service-rest/database/browser)", name), "web-service-rest")
				components = append(components, component{name: name, techType: techType})
			}

			if len(components) == 0 {
				components = []component{
					{name: "frontend", techType: "web-application"},
					{name: "backend-api", techType: "web-service-rest"},
					{name: "database", techType: "database"},
				}
				cmd.Println("No components entered — using default set: frontend, backend-api, database")
			}

			// Generate threagile.yaml (entry point)
			var sb strings.Builder
			today := time.Now().Format("2006-01-02")

			sb.WriteString(fmt.Sprintf("threagile_version: 1.0.0\n\nincludes:\n  - meta.yaml\n"))
			for _, c := range components {
				sb.WriteString(fmt.Sprintf("  - feature_%s.yaml\n", sanitizeID(c.name)))
			}
			sb.WriteString("\n")

			mainFile := filepath.Join(outDir, "threagile.yaml")
			if err := os.WriteFile(mainFile, []byte(sb.String()), 0600); err != nil {
				return fmt.Errorf("failed to write threagile.yaml: %w", err)
			}

			// Generate meta.yaml
			meta := fmt.Sprintf("title: %s\ndate: %s\n\nauthor:\n  name: %q\n\nbusiness_criticality: %s\n\nmanagement_summary_comment: >\n  %s\n",
				title, today, authorName, criticality, summary)
			if err := os.WriteFile(filepath.Join(outDir, "meta.yaml"), []byte(meta), 0600); err != nil {
				return fmt.Errorf("failed to write meta.yaml: %w", err)
			}

			// Generate one feature file per component
			for _, c := range components {
				featureFile := fmt.Sprintf(`# ============================================================
# Feature: %s
# ============================================================

technical_assets:

  %s:
    id: %s
    description: "%s component — add details here"
    type: process
    usage: business
    used_as_client_by_human: false
    out_of_scope: false
    justification_out_of_scope: ""
    size: service
    technology: %s
    tags: []
    internet: false
    machine: container
    encryption: none
    owner: %s
    confidentiality: confidential
    integrity: critical
    availability: important
    justification_cia_rating: >
      Add CIA justification here.
    multi_tenant: false
    redundant: false
    custom_developed_parts: false
    data_assets_processed: []
    data_assets_stored: []
    data_formats_accepted:
      - json
    communication_links: {}
`, c.name, c.name, sanitizeID(c.name), c.name, c.techType, authorName)

				fname := filepath.Join(outDir, fmt.Sprintf("feature_%s.yaml", sanitizeID(c.name)))
				if err := os.WriteFile(fname, []byte(featureFile), 0600); err != nil {
					return fmt.Errorf("failed to write %s: %w", fname, err)
				}
			}

			cmd.Printf("\n✓ Scaffold written to %s\n", outDir)
			cmd.Println("Files created:")
			cmd.Println("  threagile.yaml  (entry point)")
			cmd.Println("  meta.yaml       (title, author, overview)")
			for _, c := range components {
				cmd.Printf("  feature_%s.yaml\n", sanitizeID(c.name))
			}
			cmd.Println("\nNext steps:")
			cmd.Println("  1. Edit the feature files to add data assets and communication links")
			cmd.Printf("  2. Run: threagile analyze-model --model %s\n", mainFile)
			cmd.Println("  3. Run: threagile lint to check for missing descriptions")
			return nil
		},
	}

	what.rootCmd.AddCommand(initCmd)
	return what
}

// sanitizeID converts a human label to a valid Threagile ID (lowercase, hyphens).
func sanitizeID(name string) string {
	return strings.ToLower(strings.NewReplacer(" ", "-", "_", "-", "/", "-", ".", "-").Replace(name))
}
