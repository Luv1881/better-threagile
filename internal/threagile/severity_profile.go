package threagile

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/profile"
)

// initSeverityProfile adds the profile-check command and wires the --severity-profile flag
// onto the analyze-model command (applied as a post-process annotation pass).
func (what *Threagile) initSeverityProfile() *Threagile {
	cmd := &cobra.Command{
		Use:   "profile-check",
		Short: "Validate a severity-profile.yaml and display the effective weights",
		Long: `Load and validate a severity-profile.yaml file, then print the effective
CIA weight multipliers that will be applied when --severity-profile is used with analyze-model.

Example severity-profile.yaml:
  business_drivers:
    regulatory_pressure: high        # HIPAA → confidentiality ×1.5
    reputational_sensitivity: medium
    uptime_requirement: high         # SLA → availability ×2.0
  weights:
    confidentiality: 1.5  # explicit override; auto-inferred if absent
    integrity: 1.0
    availability: 2.0`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)
			p, err := profile.Load(args[0])
			if err != nil {
				return fmt.Errorf("profile-check: %w", err)
			}
			cmd.Println(p.FormatSummary())
			cmd.Printf("\nBusiness drivers:\n")
			if p.BusinessDrivers.RegulatoryPressure != "" {
				cmd.Printf("  regulatory_pressure:    %s\n", p.BusinessDrivers.RegulatoryPressure)
			}
			if p.BusinessDrivers.ReputationalSensitivity != "" {
				cmd.Printf("  reputational_sensitivity: %s\n", p.BusinessDrivers.ReputationalSensitivity)
			}
			if p.BusinessDrivers.UptimeRequirement != "" {
				cmd.Printf("  uptime_requirement:     %s\n", p.BusinessDrivers.UptimeRequirement)
			}
			cmd.Printf("\nEffective weights:\n")
			cmd.Printf("  confidentiality: %.2f×\n", p.ConfidentialityWeight())
			cmd.Printf("  integrity:       %.2f×\n", p.IntegrityWeight())
			cmd.Printf("  availability:    %.2f×\n", p.AvailabilityWeight())
			return nil
		},
	}
	what.rootCmd.AddCommand(cmd)
	return what
}
