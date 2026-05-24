package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/types"
)

type methodologyOverrideConfig struct {
	serverConfigReader
	methodology string
}

func (c methodologyOverrideConfig) GetMethodology() string {
	if strings.TrimSpace(c.methodology) == "" {
		return c.serverConfigReader.GetMethodology()
	}
	return c.methodology
}

type diffRequest struct {
	OldModel    input.Model `json:"old_model"`
	NewModel    input.Model `json:"new_model"`
	Methodology string      `json:"methodology,omitempty"`
}

type explainRiskRequest struct {
	SyntheticID string `json:"synthetic_id"`
	Methodology string `json:"methodology,omitempty"`
}

func (s *server) metaMethodologies(ginContext *gin.Context) {
	methodologies := make([]gin.H, 0, len(types.MethodologyValues()))
	for _, value := range types.MethodologyValues() {
		methodology := value.(types.Methodology)
		methodologies = append(methodologies, gin.H{
			"name":        methodology.String(),
			"title":       methodology.Title(),
			"description": methodology.Explain(),
		})
	}
	ginContext.JSON(http.StatusOK, gin.H{
		"active":        s.config.GetMethodology(),
		"methodologies": methodologies,
	})
}

func (s *server) directDiff(ginContext *gin.Context) {
	var payload diffRequest
	if err := ginContext.ShouldBindJSON(&payload); err != nil {
		ginContext.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON payload: " + err.Error()})
		return
	}

	methodology := ginContext.DefaultQuery("methodology", payload.Methodology)
	oldRisks, err := s.analyzeInputRisks(&payload.OldModel, methodology)
	if err != nil {
		ginContext.JSON(http.StatusBadRequest, gin.H{"error": "unable to analyze old model: " + err.Error()})
		return
	}
	newRisks, err := s.analyzeInputRisks(&payload.NewModel, methodology)
	if err != nil {
		ginContext.JSON(http.StatusBadRequest, gin.H{"error": "unable to analyze new model: " + err.Error()})
		return
	}

	added, removed, unchanged := diffServerRisks(oldRisks, newRisks)
	ginContext.JSON(http.StatusOK, gin.H{
		"methodology": methodologyOrDefault(methodology, s.config.GetMethodology()),
		"summary": gin.H{
			"added":     len(added),
			"removed":   len(removed),
			"unchanged": len(unchanged),
		},
		"added":     added,
		"removed":   removed,
		"unchanged": unchanged,
	})
}

func (s *server) riskTrackingSummary(ginContext *gin.Context) {
	result, ok := s.analyzeStoredModel(ginContext, ginContext.DefaultQuery("methodology", s.config.GetMethodology()))
	if !ok {
		return
	}

	byStatus := make(map[string]int)
	tracked := 0
	for _, risk := range result.ParsedModel.GeneratedRisksBySyntheticId {
		byStatus[risk.RiskStatus.String()]++
		if _, exists := result.ParsedModel.RiskTracking[risk.SyntheticId]; exists {
			tracked++
		}
	}

	total := len(result.ParsedModel.GeneratedRisksBySyntheticId)
	ginContext.JSON(http.StatusOK, gin.H{
		"methodology": result.ParsedModel.ActiveMethodology.String(),
		"total":       total,
		"tracked":     tracked,
		"untracked":   total - tracked,
		"by_status":   byStatus,
	})
}

func (s *server) explainRisk(ginContext *gin.Context) {
	var payload explainRiskRequest
	_ = ginContext.ShouldBindJSON(&payload)
	if payload.SyntheticID == "" {
		payload.SyntheticID = ginContext.Query("synthetic_id")
	}
	if payload.SyntheticID == "" {
		ginContext.JSON(http.StatusBadRequest, gin.H{"error": "synthetic_id is required"})
		return
	}

	result, ok := s.analyzeStoredModel(ginContext, ginContext.DefaultQuery("methodology", payload.Methodology))
	if !ok {
		return
	}

	risk, exists := result.ParsedModel.GeneratedRisksBySyntheticId[strings.ToLower(payload.SyntheticID)]
	if !exists {
		ginContext.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("risk %q not found", payload.SyntheticID)})
		return
	}

	category := result.ParsedModel.GetRiskCategory(risk.CategoryId)
	if category == nil {
		ginContext.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("category %q not found for risk %q", risk.CategoryId, payload.SyntheticID)})
		return
	}

	var tracking *types.RiskTracking
	if found, ok := result.ParsedModel.RiskTracking[risk.SyntheticId]; ok {
		tracking = found
	}

	active := result.ParsedModel.ActiveMethodology
	response := gin.H{
		"methodology":            active.String(),
		"classification":         category.ClassificationLabel(active),
		"risk":                   risk,
		"category":               category,
		"tracking":               tracking,
	}

	// Resolve the most relevant technical asset name for convenience.
	if risk.MostRelevantTechnicalAssetId != "" {
		if asset, ok := result.ParsedModel.TechnicalAssets[risk.MostRelevantTechnicalAssetId]; ok {
			response["most_relevant_technical_asset_title"] = asset.Title
		}
	}

	ginContext.JSON(http.StatusOK, response)
}

func (s *server) analyzeStoredModel(ginContext *gin.Context, methodology string) (*model.ReadResult, bool) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return nil, false
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return nil, false
	}

	result, err := s.analyzeInput(&modelInput, methodology)
	if err != nil {
		ginContext.JSON(http.StatusBadRequest, gin.H{"error": "unable to analyze model: " + err.Error()})
		return nil, false
	}
	return result, true
}

func (s *server) analyzeInput(modelInput *input.Model, methodology string) (*model.ReadResult, error) {
	progressReporter := DefaultProgressReporter{
		Verbose:       s.config.GetVerbose(),
		SuppressError: true,
	}
	return model.AnalyzeModel(
		modelInput,
		methodologyOverrideConfig{s.config, methodologyOrDefault(methodology, s.config.GetMethodology())},
		s.builtinRiskRules,
		s.customRiskRules,
		progressReporter,
	)
}

func (s *server) analyzeInputRisks(modelInput *input.Model, methodology string) (map[string]*types.Risk, error) {
	result, err := s.analyzeInput(modelInput, methodology)
	if err != nil {
		return nil, err
	}
	risks := make(map[string]*types.Risk)
	for _, risk := range result.ParsedModel.GeneratedRisksBySyntheticId {
		risks[risk.SyntheticId] = risk
	}
	return risks, nil
}

func diffServerRisks(oldRisks, newRisks map[string]*types.Risk) (added, removed, unchanged []*types.Risk) {
	for id, risk := range newRisks {
		if _, exists := oldRisks[id]; exists {
			unchanged = append(unchanged, risk)
		} else {
			added = append(added, risk)
		}
	}
	for id, risk := range oldRisks {
		if _, exists := newRisks[id]; !exists {
			removed = append(removed, risk)
		}
	}
	sortRisks := func(risks []*types.Risk) {
		sort.Slice(risks, func(i, j int) bool { return risks[i].SyntheticId < risks[j].SyntheticId })
	}
	sortRisks(added)
	sortRisks(removed)
	sortRisks(unchanged)
	return added, removed, unchanged
}

func methodologyOrDefault(methodology, fallback string) string {
	if strings.TrimSpace(methodology) == "" {
		return fallback
	}
	return methodology
}
