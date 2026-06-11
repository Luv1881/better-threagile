package model

import (
	"fmt"

	"github.com/threagile/threagile/pkg/input"
)

// BuildSyntheticModelInput builds a synthetic but valid model with nAssets
// technical assets (each with one data asset and a communication link to the
// previous asset, forming a chain), for use in benchmarks.
func BuildSyntheticModelInput(nAssets int) *input.Model {
	technicalAssets := make(map[string]input.TechnicalAsset, nAssets)
	dataAssets := make(map[string]input.DataAsset, nAssets)

	for i := 0; i < nAssets; i++ {
		daID := fmt.Sprintf("data-%d", i)
		dataAssets[daID] = input.DataAsset{
			ID:              daID,
			Usage:           "business",
			Quantity:        "few",
			Confidentiality: "confidential",
			Integrity:       "critical",
			Availability:    "critical",
		}

		taID := fmt.Sprintf("asset-%d", i)
		ta := input.TechnicalAsset{
			ID:                  taID,
			Usage:               "business",
			Type:                "process",
			Size:                "system",
			Technology:          "web-application",
			Encryption:          "none",
			Machine:             "virtual",
			Confidentiality:     "confidential",
			Integrity:           "critical",
			Availability:        "critical",
			DataAssetsProcessed: []string{daID},
			DataAssetsStored:    []string{daID},
		}
		if i > 0 {
			ta.CommunicationLinks = map[string]input.CommunicationLink{
				"to-previous": {
					Target:             fmt.Sprintf("asset-%d", i-1),
					Protocol:           "https",
					Authentication:     "token",
					Authorization:      "technical-user",
					Usage:              "business",
					DataAssetsSent:     []string{daID},
					DataAssetsReceived: []string{daID},
				},
			}
		}
		technicalAssets[taID] = ta
	}

	return &input.Model{
		Title:               "Synthetic Benchmark Model",
		BusinessCriticality: "important",
		TechnicalAssets:     technicalAssets,
		DataAssets:          dataAssets,
	}
}
