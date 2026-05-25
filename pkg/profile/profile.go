// Package profile provides per-organisation severity-weighting overlays.
// A severity-profile.yaml file declares business drivers (regulatory pressure,
// reputational sensitivity, uptime requirement) and CIA weight multipliers that
// are applied when computing impact scores.
package profile

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SeverityProfile is the top-level structure of a severity-profile.yaml file.
type SeverityProfile struct {
	BusinessDrivers BusinessDrivers    `yaml:"business_drivers"`
	Weights         CIAWeights         `yaml:"weights"`
}

// BusinessDrivers describes the high-level risk context of the organisation.
type BusinessDrivers struct {
	// RegulatoryPressure: low | medium | high
	// high → confidentiality weight auto-boosted by 1.5× unless overridden in Weights
	RegulatoryPressure string `yaml:"regulatory_pressure"`
	// ReputationalSensitivity: low | medium | high
	ReputationalSensitivity string `yaml:"reputational_sensitivity"`
	// UptimeRequirement: low | medium | high
	// high → availability weight auto-boosted by 2× unless overridden in Weights
	UptimeRequirement string `yaml:"uptime_requirement"`
}

// CIAWeights are multipliers applied to the computed impact for each CIA dimension.
// Values of 0 are treated as 1.0 (no override).
type CIAWeights struct {
	Confidentiality float64 `yaml:"confidentiality"`
	Integrity       float64 `yaml:"integrity"`
	Availability    float64 `yaml:"availability"`
}

// Default returns a SeverityProfile with neutral (1.0) weights.
func Default() *SeverityProfile {
	return &SeverityProfile{
		Weights: CIAWeights{
			Confidentiality: 1.0,
			Integrity:       1.0,
			Availability:    1.0,
		},
	}
}

// Load reads and validates a severity-profile.yaml file.
func Load(path string) (*SeverityProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: read %s: %w", path, err)
	}
	var p SeverityProfile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("profile: parse %s: %w", path, err)
	}
	p.applyDriverDefaults()
	p.normalise()
	return &p, nil
}

// applyDriverDefaults infers weights from business drivers when weights are unset.
func (p *SeverityProfile) applyDriverDefaults() {
	if p.Weights.Confidentiality == 0 {
		switch strings.ToLower(p.BusinessDrivers.RegulatoryPressure) {
		case "high":
			p.Weights.Confidentiality = 1.5
		case "medium":
			p.Weights.Confidentiality = 1.2
		default:
			p.Weights.Confidentiality = 1.0
		}
	}
	if p.Weights.Availability == 0 {
		switch strings.ToLower(p.BusinessDrivers.UptimeRequirement) {
		case "high":
			p.Weights.Availability = 2.0
		case "medium":
			p.Weights.Availability = 1.3
		default:
			p.Weights.Availability = 1.0
		}
	}
	if p.Weights.Integrity == 0 {
		switch strings.ToLower(p.BusinessDrivers.ReputationalSensitivity) {
		case "high", "medium":
			p.Weights.Integrity = 1.3
		default:
			p.Weights.Integrity = 1.0
		}
	}
}

// normalise clamps weights to [0.1, 5.0] to prevent nonsensical values.
func (p *SeverityProfile) normalise() {
	clamp := func(v float64) float64 {
		if v < 0.1 {
			return 0.1
		}
		if v > 5.0 {
			return 5.0
		}
		return v
	}
	p.Weights.Confidentiality = clamp(p.Weights.Confidentiality)
	p.Weights.Integrity = clamp(p.Weights.Integrity)
	p.Weights.Availability = clamp(p.Weights.Availability)
}

// ConfidentialityWeight returns the weight for confidentiality (never 0).
func (p *SeverityProfile) ConfidentialityWeight() float64 {
	if p == nil || p.Weights.Confidentiality == 0 {
		return 1.0
	}
	return p.Weights.Confidentiality
}

// IntegrityWeight returns the weight for integrity (never 0).
func (p *SeverityProfile) IntegrityWeight() float64 {
	if p == nil || p.Weights.Integrity == 0 {
		return 1.0
	}
	return p.Weights.Integrity
}

// AvailabilityWeight returns the weight for availability (never 0).
func (p *SeverityProfile) AvailabilityWeight() float64 {
	if p == nil || p.Weights.Availability == 0 {
		return 1.0
	}
	return p.Weights.Availability
}

// WeightForSTRIDECategory returns the relevant CIA weight for a STRIDE category string.
// Used during report rendering to annotate severity adjustments.
func (p *SeverityProfile) WeightForSTRIDECategory(strideCategory string) float64 {
	if p == nil {
		return 1.0
	}
	switch strings.ToLower(strideCategory) {
	case "spoofing", "repudiation", "information-disclosure":
		return p.ConfidentialityWeight()
	case "tampering":
		return p.IntegrityWeight()
	case "denial-of-service":
		return p.AvailabilityWeight()
	case "elevation-of-privilege", "lateral-movement":
		// Elevation of privilege and lateral movement affect all three — use max weight
		c := p.ConfidentialityWeight()
		i := p.IntegrityWeight()
		a := p.AvailabilityWeight()
		if c > i && c > a {
			return c
		}
		if i > a {
			return i
		}
		return a
	default:
		return 1.0
	}
}

// AdjustedImpactScore multiplies a raw 0–4 impact score by the appropriate CIA weight
// and returns a float that callers can use to bump/demote severity buckets.
// scale is the CIA dimension string: "confidentiality", "integrity", "availability".
func (p *SeverityProfile) AdjustedImpactScore(rawScore float64, dimension string) float64 {
	if p == nil {
		return rawScore
	}
	switch strings.ToLower(dimension) {
	case "confidentiality":
		return rawScore * p.ConfidentialityWeight()
	case "integrity":
		return rawScore * p.IntegrityWeight()
	case "availability":
		return rawScore * p.AvailabilityWeight()
	default:
		return rawScore
	}
}

// FormatSummary returns a one-line human-readable description of the active weights.
func (p *SeverityProfile) FormatSummary() string {
	if p == nil {
		return "severity profile: default (all weights 1.0)"
	}
	return fmt.Sprintf(
		"severity profile: confidentiality×%.1f  integrity×%.1f  availability×%.1f",
		p.ConfidentialityWeight(), p.IntegrityWeight(), p.AvailabilityWeight(),
	)
}
