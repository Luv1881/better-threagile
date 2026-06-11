package macros

import (
	"sort"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

type AddBuildPipeline struct {
	macroState             map[string][]string
	questionsAnswered      []string
	codeInspectionUsed     bool
	containerTechUsed      bool
	withinTrustBoundary    bool
	createNewTrustBoundary bool
}

func NewBuildPipeline() *AddBuildPipeline {
	return &AddBuildPipeline{
		macroState:        make(map[string][]string),
		questionsAnswered: make([]string, 0),
	}
}

var pushOrPull = []string{
	"Push-based Deployment (build pipeline deploys towards target asset)",
	"Pull-based Deployment (deployment target asset fetches deployment from registry)",
}

func (m *AddBuildPipeline) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:    "add-build-pipeline",
		Title: "Add Build Pipeline",
		Description: "This model macro adds a build pipeline (development client, build pipeline, artifact registry, container image registry, " +
			"source code repository, etc.) to the model.",
	}
}

// TODO add question for type of machine (either physical, virtual, container, etc.)

func (m *AddBuildPipeline) GetNextQuestion(model *types.Model) (nextQuestion MacroQuestion, err error) {
	counter := len(m.questionsAnswered)
	if counter > 3 && !m.codeInspectionUsed {
		counter++
	}
	if counter > 5 && !m.containerTechUsed {
		counter += 2
	}
	if counter > 12 && !m.withinTrustBoundary {
		counter++
	}
	if counter > 13 && !m.createNewTrustBoundary {
		counter++
	}
	switch counter {
	case 0:
		return MacroQuestion{
			ID:              "source-repository",
			Title:           "What product is used as the sourcecode repository?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Git",
		}, nil
	case 1:
		return MacroQuestion{
			ID:              "build-pipeline",
			Title:           "What product is used as the build pipeline?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Jenkins",
		}, nil
	case 2:
		return MacroQuestion{
			ID:              "artifact-registry",
			Title:           "What product is used as the artifact registry?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Nexus",
		}, nil
	case 3:
		return MacroQuestion{
			ID:              "code-inspection-used",
			Title:           "Are code inspection platforms (like SonarQube) used?",
			Description:     "This affects whether code inspection platform are added.",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 4:
		return MacroQuestion{
			ID:              types.CodeInspectionPlatform,
			Title:           "What product is used as the code inspection platform?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "SonarQube",
		}, nil
	case 5:
		return MacroQuestion{
			ID:              "container-technology-used",
			Title:           "Is container technology (like Docker) used?",
			Description:     "This affects whether container registries are added.",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 6:
		return MacroQuestion{
			ID:              "container-registry",
			Title:           "What product is used as the container registry?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Docker",
		}, nil
	case 7:
		return MacroQuestion{
			ID:              "container-platform",
			Title:           "What product is used as the container platform (for orchestration and runtime)?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Kubernetes",
		}, nil
	case 8:
		return MacroQuestion{
			ID:              "internet",
			Title:           "Are build pipeline components exposed on the internet?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 9:
		return MacroQuestion{
			ID:              "multi-tenant",
			Title:           "Are build pipeline components used by multiple tenants?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 10:
		return MacroQuestion{
			ID:              "encryption",
			Title:           "Are build pipeline components encrypted?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 11:
		possibleAnswers := make([]string, 0)
		for id := range model.TechnicalAssets {
			possibleAnswers = append(possibleAnswers, id)
		}
		sort.Strings(possibleAnswers)
		if len(possibleAnswers) > 0 {
			return MacroQuestion{
				ID:              "deploy-targets",
				Title:           "Select all technical assets where the build pipeline deploys to:",
				Description:     "This affects the communication links being generated.",
				PossibleAnswers: possibleAnswers,
				MultiSelect:     true,
				DefaultAnswer:   "",
			}, nil
		}
	case 12:
		return MacroQuestion{
			ID:              "within-trust-boundary",
			Title:           "Are the server-side components of the build pipeline components within a network trust boundary?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 13:
		possibleAnswers := []string{createNewTrustBoundaryLabel}
		for id, trustBoundary := range model.TrustBoundaries {
			if trustBoundary.Type.IsNetworkBoundary() {
				possibleAnswers = append(possibleAnswers, id)
			}
		}
		sort.Strings(possibleAnswers)
		return MacroQuestion{
			ID:              "selected-trust-boundary",
			Title:           "Choose from the list of existing network trust boundaries or create a new one?",
			Description:     "",
			PossibleAnswers: possibleAnswers,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	case 14:
		return MacroQuestion{
			ID:          "new-trust-boundary-type",
			Title:       "Of which type shall the new trust boundary be?",
			Description: "",
			PossibleAnswers: []string{types.NetworkOnPrem.String(),
				types.NetworkDedicatedHoster.String(),
				types.NetworkVirtualLAN.String(),
				types.NetworkCloudProvider.String(),
				types.NetworkCloudSecurityGroup.String(),
				types.NetworkPolicyNamespaceIsolation.String()},
			MultiSelect:   false,
			DefaultAnswer: types.NetworkOnPrem.String(),
		}, nil
	case 15:
		return MacroQuestion{
			ID:              "push-or-pull",
			Title:           "What type of deployment strategy is used?",
			Description:     "Push-based deployments are more classic ones and pull-based are more GitOps-like ones.",
			PossibleAnswers: pushOrPull,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	case 16:
		return MacroQuestion{
			ID:              "owner",
			Title:           "Who is the owner of the build pipeline and runtime assets?",
			Description:     "This name affects the technical asset's and data asset's owner.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	}
	return NoMoreQuestions(), nil
}

func (m *AddBuildPipeline) ApplyAnswer(questionID string, answer ...string) (message string, validResult bool, err error) {
	m.macroState[questionID] = answer
	m.questionsAnswered = append(m.questionsAnswered, questionID)
	switch questionID {
	case "code-inspection-used":
		m.codeInspectionUsed = strings.EqualFold(m.macroState["code-inspection-used"][0], "yes")
	case "container-technology-used":
		m.containerTechUsed = strings.EqualFold(m.macroState["container-technology-used"][0], "yes")
	case "within-trust-boundary":
		m.withinTrustBoundary = strings.EqualFold(m.macroState["within-trust-boundary"][0], "yes")
	case "selected-trust-boundary":
		m.createNewTrustBoundary = strings.EqualFold(m.macroState["selected-trust-boundary"][0], createNewTrustBoundaryLabel)
	}

	return "Answer processed", true, nil
}

func (m *AddBuildPipeline) GoBack() (message string, validResult bool, err error) {
	if len(m.questionsAnswered) == 0 {
		return "Cannot go back further", false, nil
	}
	lastQuestionID := m.questionsAnswered[len(m.questionsAnswered)-1]
	m.questionsAnswered = m.questionsAnswered[:len(m.questionsAnswered)-1]
	delete(m.macroState, lastQuestionID)
	return "Undo successful", true, nil
}

func (m *AddBuildPipeline) GetFinalChangeImpact(modelInput *input.Model, model *types.Model) (changes []string, message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult, err = m.applyChange(modelInput, model, &changeLogCollector, true)
	return changeLogCollector, message, validResult, err
}
