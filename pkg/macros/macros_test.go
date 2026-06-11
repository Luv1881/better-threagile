package macros_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/threagile/threagile/internal/threagile"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/macros"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/server"
	"github.com/threagile/threagile/pkg/types"
)

// loadFixture parses and analyzes the canonical demo/example model, returning
// both the raw model input (mutated by macros) and the analyzed model.
func loadFixture(t *testing.T) (*input.Model, *types.Model) {
	t.Helper()

	modelPath, err := filepath.Abs(filepath.Join("..", "..", "demo", "example", "threagile.yaml"))
	require.NoError(t, err)

	cfg := new(threagile.Config).Defaults("test")
	cfg.SetInputFile(modelPath)
	cfg.SetOutputFolder(t.TempDir())
	cfg.SetTempFolder(t.TempDir())

	result, analyzeErr := model.ReadAndAnalyzeModel(cfg, risks.GetBuiltInRiskRules(), server.DefaultProgressReporter{})
	require.NoError(t, analyzeErr)
	return result.ModelInput, result.ParsedModel
}

func TestListBuiltInMacros(t *testing.T) {
	all := macros.ListBuiltInMacros()
	assert.NotEmpty(t, all)

	ids := make(map[string]bool)
	for _, m := range all {
		details := m.GetMacroDetails()
		assert.NotEmpty(t, details.ID)
		assert.NotEmpty(t, details.Title)
		ids[details.ID] = true
	}

	for _, id := range []string{"add-build-pipeline", "add-vault", "pretty-print", "remove-unused-tags", "seed-risk-tracking", "seed-tags", "discover-attack-surface"} {
		assert.True(t, ids[id], "expected built-in macro %q", id)
	}
}

func TestGetMacroByID(t *testing.T) {
	m, err := macros.GetMacroByID("seed-tags")
	require.NoError(t, err)
	assert.Equal(t, "seed-tags", m.GetMacroDetails().ID)

	_, err = macros.GetMacroByID("does-not-exist")
	assert.Error(t, err)
}

// driveQuestions runs the GetNextQuestion/ApplyAnswer loop until no more
// questions remain, picking an answer for each question ID from `answers`,
// falling back to the question's default answer or first possible answer.
func driveQuestions(t *testing.T, m macros.Macros, parsedModel *types.Model, answers map[string]string) {
	t.Helper()

	for i := 0; i < 100; i++ {
		question, err := m.GetNextQuestion(parsedModel)
		require.NoError(t, err)
		if question.NoMoreQuestions() {
			return
		}

		answer, ok := answers[question.ID]
		if !ok {
			answer = question.DefaultAnswer
		}
		if answer == "" && len(question.PossibleAnswers) > 0 {
			answer = question.PossibleAnswers[0]
		}

		_, _, err = m.ApplyAnswer(question.ID, answer)
		require.NoError(t, err)
	}

	t.Fatal("question loop did not terminate")
}

func TestPrettyPrintMacro(t *testing.T) {
	m := macros.ListBuiltInMacros()[0]
	for _, macro := range macros.ListBuiltInMacros() {
		if macro.GetMacroDetails().ID == "pretty-print" {
			m = macro
		}
	}

	modelInput, parsedModel := loadFixture(t)

	question, err := m.GetNextQuestion(parsedModel)
	require.NoError(t, err)
	assert.True(t, question.NoMoreQuestions())

	changes, message, valid, err := m.GetFinalChangeImpact(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotEmpty(t, changes)
	assert.NotEmpty(t, message)

	message, valid, err = m.Execute(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotEmpty(t, message)
}

func TestSeedTagsMacro(t *testing.T) {
	m, err := macros.GetMacroByID("seed-tags")
	require.NoError(t, err)

	modelInput, parsedModel := loadFixture(t)
	modelInput.TagsAvailable = nil

	message, valid, err := m.Execute(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Contains(t, message, "tags successful")
	assert.GreaterOrEqual(t, len(modelInput.TagsAvailable), len(parsedModel.AllSupportedTags))
	for tag := range parsedModel.AllSupportedTags {
		assert.Contains(t, modelInput.TagsAvailable, tag)
	}
}

func TestRemoveUnusedTagsMacro(t *testing.T) {
	m, err := macros.GetMacroByID("remove-unused-tags")
	require.NoError(t, err)

	modelInput, parsedModel := loadFixture(t)
	// Add an unused tag that isn't referenced anywhere in the model.
	modelInput.TagsAvailable = append(modelInput.TagsAvailable, "totally-unused-tag-xyz")

	message, valid, err := m.Execute(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Contains(t, message, "unused tags successful")
	assert.NotContains(t, modelInput.TagsAvailable, "totally-unused-tag-xyz")
}

func TestSeedRiskTrackingMacro(t *testing.T) {
	m, err := macros.GetMacroByID("seed-risk-tracking")
	require.NoError(t, err)

	modelInput, parsedModel := loadFixture(t)
	modelInput.RiskTracking = make(map[string]input.RiskTracking)

	require.NotEmpty(t, parsedModel.GeneratedRisksBySyntheticId, "fixture model should generate at least one risk")

	expectedUntracked := 0
	for _, risk := range parsedModel.GeneratedRisksBySyntheticId {
		if !parsedModel.IsRiskTracked(risk) {
			expectedUntracked++
		}
	}
	require.Greater(t, expectedUntracked, 0, "fixture model should have at least one untracked risk")

	message, valid, err := m.Execute(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Contains(t, message, "initial risk tracking successful")
	assert.Equal(t, expectedUntracked, len(modelInput.RiskTracking))
	for _, tracking := range modelInput.RiskTracking {
		assert.Equal(t, types.Unchecked.String(), tracking.Status)
	}
}

func TestDiscoverAttackSurfaceMacro(t *testing.T) {
	m, err := macros.GetMacroByID("discover-attack-surface")
	require.NoError(t, err)

	modelInput, parsedModel := loadFixture(t)

	question, err := m.GetNextQuestion(parsedModel)
	require.NoError(t, err)
	assert.True(t, question.NoMoreQuestions())

	_, message, valid, err := m.GetFinalChangeImpact(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotEmpty(t, message)

	message, valid, err = m.Execute(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Contains(t, message, "internet-exposed assets")
}

func TestAddVaultMacro(t *testing.T) {
	m, err := macros.GetMacroByID("add-vault")
	require.NoError(t, err)

	modelInput, parsedModel := loadFixture(t)
	dataAssetsBefore := len(modelInput.DataAssets)
	techAssetsBefore := len(modelInput.TechnicalAssets)

	driveQuestions(t, m, parsedModel, map[string]string{
		"vault-name":            "HashiCorp Vault",
		"multi-tenant":          "No",
		"within-trust-boundary": "No",
	})

	changes, message, valid, err := m.GetFinalChangeImpact(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotEmpty(t, changes)
	assert.NotEmpty(t, message)

	message, valid, err = m.Execute(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotEmpty(t, message)

	assert.Greater(t, len(modelInput.DataAssets), dataAssetsBefore)
	assert.Greater(t, len(modelInput.TechnicalAssets), techAssetsBefore)
}

func TestAddBuildPipelineMacro(t *testing.T) {
	m, err := macros.GetMacroByID("add-build-pipeline")
	require.NoError(t, err)

	modelInput, parsedModel := loadFixture(t)
	techAssetsBefore := len(modelInput.TechnicalAssets)

	driveQuestions(t, m, parsedModel, map[string]string{
		"internet":              "No",
		"multi-tenant":          "No",
		"encryption":            "None",
		"within-trust-boundary": "No",
		"push-or-pull":          "Push-based Deployment",
	})

	changes, message, valid, err := m.GetFinalChangeImpact(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotEmpty(t, changes)
	assert.NotEmpty(t, message)

	message, valid, err = m.Execute(modelInput, parsedModel)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotEmpty(t, message)

	assert.Greater(t, len(modelInput.TechnicalAssets), techAssetsBefore)
}
