package macros

import (
	"fmt"
	"strings"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

func (m *AddBuildPipeline) Execute(modelInput *input.Model, model *types.Model) (message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult, err = m.applyChange(modelInput, model, &changeLogCollector, false)
	return message, validResult, err
}

func (m *AddBuildPipeline) applyChange(modelInput *input.Model, parsedModel *types.Model, changeLogCollector *[]string, dryRun bool) (message string, validResult bool, err error) {
	var serverSideTechAssets = make([]string, 0)
	// ################################################
	modelInput.AddTagToModelInput(m.macroState["source-repository"][0], dryRun, changeLogCollector)
	modelInput.AddTagToModelInput(m.macroState["build-pipeline"][0], dryRun, changeLogCollector)
	modelInput.AddTagToModelInput(m.macroState["artifact-registry"][0], dryRun, changeLogCollector)
	if m.containerTechUsed {
		modelInput.AddTagToModelInput(m.macroState["container-registry"][0], dryRun, changeLogCollector)
		modelInput.AddTagToModelInput(m.macroState["container-platform"][0], dryRun, changeLogCollector)
	}
	if m.codeInspectionUsed {
		modelInput.AddTagToModelInput(m.macroState[types.CodeInspectionPlatform][0], dryRun, changeLogCollector)
	}

	sourceRepoID := types.MakeID(m.macroState["source-repository"][0]) + "-sourcecode-repository"
	buildPipelineID := types.MakeID(m.macroState["build-pipeline"][0]) + "-build-pipeline"
	artifactRegistryID := types.MakeID(m.macroState["artifact-registry"][0]) + "-artifact-registry"
	containerRepoID, containerPlatformID, containerSharedRuntimeID := "", "", ""
	if m.containerTechUsed {
		containerRepoID = types.MakeID(m.macroState["container-registry"][0]) + "-container-registry"
		containerPlatformID = types.MakeID(m.macroState["container-platform"][0]) + "-container-platform"
		containerSharedRuntimeID = types.MakeID(m.macroState["container-platform"][0]) + "-container-runtime"
	}
	codeInspectionPlatformID := ""
	if m.codeInspectionUsed {
		codeInspectionPlatformID = types.MakeID(m.macroState[types.CodeInspectionPlatform][0]) + "-code-inspection-platform"
	}
	owner := m.macroState["owner"][0]

	if _, exists := parsedModel.DataAssets["Sourcecode"]; !exists {
		dataAsset := input.DataAsset{
			ID:              "sourcecode",
			Description:     "Sourcecode to build the application components from",
			Usage:           types.DevOps.String(),
			Tags:            []string{},
			Origin:          "",
			Owner:           owner,
			Quantity:        types.Few.String(),
			Confidentiality: types.Confidential.String(),
			Integrity:       types.Critical.String(),
			Availability:    types.Important.String(),
			JustificationCiaRating: "Sourcecode is at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
		}
		*changeLogCollector = append(*changeLogCollector, "adding data asset: sourcecode")
		if !dryRun {
			modelInput.DataAssets["Sourcecode"] = dataAsset
		}
	}

	if _, exists := parsedModel.DataAssets["Deployment"]; !exists {
		dataAsset := input.DataAsset{
			ID:              "deployment",
			Description:     "Deployment unit being installed/shipped",
			Usage:           types.DevOps.String(),
			Tags:            []string{},
			Origin:          "",
			Owner:           owner,
			Quantity:        types.VeryFew.String(),
			Confidentiality: types.Confidential.String(),
			Integrity:       types.Critical.String(),
			Availability:    types.Important.String(),
			JustificationCiaRating: "Deployment units are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
		}
		*changeLogCollector = append(*changeLogCollector, "adding data asset: deployment")
		if !dryRun {
			modelInput.DataAssets["Deployment"] = dataAsset
		}
	}

	id := "development-client"
	if _, exists := parsedModel.TechnicalAssets[id]; !exists {
		encryption := types.NoneEncryption.String()
		if strings.EqualFold(m.macroState["encryption"][0], "yes") {
			encryption = types.Transparent.String()
		}

		commLinks := make(map[string]input.CommunicationLink)
		commLinks["Sourcecode Repository Traffic"] = input.CommunicationLink{
			Target:                 sourceRepoID,
			Description:            "Sourcecode Repository Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.EndUserIdentityPropagation.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               false,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         []string{"sourcecode"},
			DataAssetsReceived:     []string{"sourcecode"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		commLinks["Build Pipeline Traffic"] = input.CommunicationLink{
			Target:                 buildPipelineID,
			Description:            "Build Pipeline Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.EndUserIdentityPropagation.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               true,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         nil,
			DataAssetsReceived:     []string{"deployment"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		commLinks["Artifact Registry Traffic"] = input.CommunicationLink{
			Target:                 artifactRegistryID,
			Description:            "Artifact Registry Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.EndUserIdentityPropagation.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               true,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         nil,
			DataAssetsReceived:     []string{"deployment"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		if m.containerTechUsed {
			commLinks["Container Registry Traffic"] = input.CommunicationLink{
				Target:                 containerRepoID,
				Description:            "Container Registry Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.EndUserIdentityPropagation.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               false,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         []string{"deployment"},
				DataAssetsReceived:     []string{"deployment"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
			commLinks["Container Platform Traffic"] = input.CommunicationLink{
				Target:                 containerPlatformID,
				Description:            "Container Platform Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.EndUserIdentityPropagation.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               false,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         []string{"deployment"},
				DataAssetsReceived:     []string{"deployment"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
		}
		if m.codeInspectionUsed {
			commLinks["Code Inspection Platform Traffic"] = input.CommunicationLink{
				Target:                 codeInspectionPlatformID,
				Description:            "Code Inspection Platform Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.EndUserIdentityPropagation.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               true,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         nil,
				DataAssetsReceived:     []string{"sourcecode"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
		}

		techAsset := input.TechnicalAsset{
			ID:                      id,
			Description:             "Development Client",
			Type:                    types.ExternalEntity.String(),
			Usage:                   types.DevOps.String(),
			UsedAsClientByHuman:     true,
			OutOfScope:              true,
			JustificationOutOfScope: "Development client is not directly in-scope of the application.",
			Size:                    types.System.String(),
			Technology:              types.DevOpsClient,
			Tags:                    []string{},
			Internet:                strings.EqualFold(m.macroState["internet"][0], "yes"),
			Machine:                 types.Physical.String(),
			Encryption:              encryption,
			Owner:                   owner,
			Confidentiality:         types.Confidential.String(),
			Integrity:               types.Critical.String(),
			Availability:            types.Important.String(),
			JustificationCiaRating: "Sourcecode processing components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			MultiTenant:          false,
			Redundant:            false,
			CustomDevelopedParts: false,
			DataAssetsProcessed:  []string{"sourcecode", "deployment"},
			DataAssetsStored:     []string{"sourcecode", "deployment"},
			DataFormatsAccepted:  []string{"file"},
			CommunicationLinks:   commLinks,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.TechnicalAssets["Development Client"] = techAsset
		}
	}

	id = sourceRepoID
	if _, exists := parsedModel.TechnicalAssets[id]; !exists {
		serverSideTechAssets = append(serverSideTechAssets, id)
		encryption := types.NoneEncryption.String()
		if strings.EqualFold(m.macroState["encryption"][0], "yes") {
			encryption = types.Transparent.String()
		}
		techAsset := input.TechnicalAsset{
			ID:                      id,
			Description:             m.macroState["source-repository"][0] + " Sourcecode Repository",
			Type:                    types.Process.String(),
			Usage:                   types.DevOps.String(),
			UsedAsClientByHuman:     false,
			OutOfScope:              false,
			JustificationOutOfScope: "",
			Size:                    types.Service.String(),
			Technology:              types.SourcecodeRepository,
			Tags:                    []string{input.NormalizeTag(m.macroState["source-repository"][0])},
			Internet:                strings.EqualFold(m.macroState["internet"][0], "yes"),
			Machine:                 types.Virtual.String(),
			Encryption:              encryption,
			Owner:                   owner,
			Confidentiality:         types.Confidential.String(),
			Integrity:               types.Critical.String(),
			Availability:            types.Important.String(),
			JustificationCiaRating: "Sourcecode processing components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			MultiTenant:          strings.EqualFold(m.macroState["multi-tenant"][0], "yes"),
			Redundant:            false,
			CustomDevelopedParts: false,
			DataAssetsProcessed:  []string{"sourcecode"},
			DataAssetsStored:     []string{"sourcecode"},
			DataFormatsAccepted:  []string{"file"},
			CommunicationLinks:   nil,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.TechnicalAssets[m.macroState["source-repository"][0]+" Sourcecode Repository"] = techAsset
		}
	}

	if m.containerTechUsed {
		id = containerRepoID
		if _, exists := parsedModel.TechnicalAssets[id]; !exists {
			serverSideTechAssets = append(serverSideTechAssets, id)
			encryption := types.NoneEncryption.String()
			if strings.EqualFold(m.macroState["encryption"][0], "yes") {
				encryption = types.Transparent.String()
			}
			techAsset := input.TechnicalAsset{
				ID:                      id,
				Description:             m.macroState["container-registry"][0] + " Container Registry",
				Type:                    types.Process.String(),
				Usage:                   types.DevOps.String(),
				UsedAsClientByHuman:     false,
				OutOfScope:              false,
				JustificationOutOfScope: "",
				Size:                    types.Service.String(),
				Technology:              types.ArtifactRegistry,
				Tags:                    []string{input.NormalizeTag(m.macroState["container-registry"][0])},
				Internet:                strings.EqualFold(m.macroState["internet"][0], "yes"),
				Machine:                 types.Virtual.String(),
				Encryption:              encryption,
				Owner:                   owner,
				Confidentiality:         types.Confidential.String(),
				Integrity:               types.Critical.String(),
				Availability:            types.Important.String(),
				JustificationCiaRating: "Container registry components are at least rated as 'critical' in terms of integrity, because any " +
					"malicious modification of it might lead to a backdoored production system.",
				MultiTenant:          strings.EqualFold(m.macroState["multi-tenant"][0], "yes"),
				Redundant:            false,
				CustomDevelopedParts: false,
				DataAssetsProcessed:  []string{"deployment"},
				DataAssetsStored:     []string{"deployment"},
				DataFormatsAccepted:  []string{"file"},
				CommunicationLinks:   nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
			if !dryRun {
				modelInput.TechnicalAssets[m.macroState["container-registry"][0]+" Container Registry"] = techAsset
			}
		}

		id = containerPlatformID
		if _, exists := parsedModel.TechnicalAssets[id]; !exists {
			serverSideTechAssets = append(serverSideTechAssets, id)
			encryption := types.NoneEncryption.String()
			if strings.EqualFold(m.macroState["encryption"][0], "yes") {
				encryption = types.Transparent.String()
			}
			techAsset := input.TechnicalAsset{
				ID:                      id,
				Description:             m.macroState["container-platform"][0] + " Container Platform",
				Type:                    types.Process.String(),
				Usage:                   types.DevOps.String(),
				UsedAsClientByHuman:     false,
				OutOfScope:              false,
				JustificationOutOfScope: "",
				Size:                    types.System.String(),
				Technology:              types.ContainerPlatform,
				Tags:                    []string{input.NormalizeTag(m.macroState["container-platform"][0])},
				Internet:                strings.EqualFold(m.macroState["internet"][0], "yes"),
				Machine:                 types.Virtual.String(),
				Encryption:              encryption,
				Owner:                   owner,
				Confidentiality:         types.Confidential.String(),
				Integrity:               types.MissionCritical.String(),
				Availability:            types.MissionCritical.String(),
				JustificationCiaRating: "Container platform components are rated as 'mission-critical' in terms of integrity and availability, because any " +
					"malicious modification of it might lead to a backdoored production system.",
				MultiTenant:          strings.EqualFold(m.macroState["multi-tenant"][0], "yes"),
				Redundant:            false,
				CustomDevelopedParts: false,
				DataAssetsProcessed:  []string{"deployment"},
				DataAssetsStored:     []string{"deployment"},
				DataFormatsAccepted:  []string{"file"},
				CommunicationLinks:   nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
			if !dryRun {
				modelInput.TechnicalAssets[m.macroState["container-platform"][0]+" Container Platform"] = techAsset
			}
		}
	}

	id = buildPipelineID
	if _, exists := parsedModel.TechnicalAssets[id]; !exists {
		serverSideTechAssets = append(serverSideTechAssets, id)
		encryption := types.NoneEncryption.String()
		if strings.EqualFold(m.macroState["encryption"][0], "yes") {
			encryption = types.Transparent.String()
		}

		commLinks := make(map[string]input.CommunicationLink)
		commLinks["Sourcecode Repository Traffic"] = input.CommunicationLink{
			Target:                 sourceRepoID,
			Description:            "Sourcecode Repository Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.TechnicalUser.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               true,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         nil,
			DataAssetsReceived:     []string{"sourcecode"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		commLinks["Artifact Registry Traffic"] = input.CommunicationLink{
			Target:                 artifactRegistryID,
			Description:            "Artifact Registry Traffic",
			Protocol:               types.HTTPS.String(),
			Authentication:         types.Credentials.String(),
			Authorization:          types.TechnicalUser.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               false,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         []string{"deployment"},
			DataAssetsReceived:     []string{"deployment"},
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
		if m.containerTechUsed {
			commLinks["Container Registry Traffic"] = input.CommunicationLink{
				Target:                 containerRepoID,
				Description:            "Container Registry Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.TechnicalUser.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               false,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         []string{"deployment"},
				DataAssetsReceived:     []string{"deployment"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
			if m.macroState["push-or-pull"][0] == pushOrPull[0] { // Push
				commLinks["Container Platform Push"] = input.CommunicationLink{
					Target:                 containerPlatformID,
					Description:            "Container Platform Push",
					Protocol:               types.HTTPS.String(),
					Authentication:         types.Credentials.String(),
					Authorization:          types.TechnicalUser.String(),
					Tags:                   []string{},
					VPN:                    false,
					IpFiltered:             false,
					Readonly:               false,
					Usage:                  types.DevOps.String(),
					DataAssetsSent:         []string{"deployment"},
					DataAssetsReceived:     []string{"deployment"},
					DiagramTweakWeight:     0,
					DiagramTweakConstraint: false,
				}
			} else { // Pull
				commLinkPull := input.CommunicationLink{
					Target:                 containerRepoID,
					Description:            "Container Platform Pull",
					Protocol:               types.HTTPS.String(),
					Authentication:         types.Credentials.String(),
					Authorization:          types.TechnicalUser.String(),
					Tags:                   []string{},
					VPN:                    false,
					IpFiltered:             false,
					Readonly:               true,
					Usage:                  types.DevOps.String(),
					DataAssetsSent:         nil,
					DataAssetsReceived:     []string{"deployment"},
					DiagramTweakWeight:     0,
					DiagramTweakConstraint: false,
				}
				if !dryRun {
					titleOfTargetAsset := m.macroState["container-platform"][0] + " Container Platform"
					containerPlatform := modelInput.TechnicalAssets[titleOfTargetAsset]
					if containerPlatform.CommunicationLinks == nil {
						containerPlatform.CommunicationLinks = make(map[string]input.CommunicationLink)
					}
					containerPlatform.CommunicationLinks["Container Platform Pull"] = commLinkPull
					modelInput.TechnicalAssets[titleOfTargetAsset] = containerPlatform
				}
			}
		}
		if m.codeInspectionUsed {
			commLinks["Code Inspection Platform Traffic"] = input.CommunicationLink{
				Target:                 codeInspectionPlatformID,
				Description:            "Code Inspection Platform Traffic",
				Protocol:               types.HTTPS.String(),
				Authentication:         types.Credentials.String(),
				Authorization:          types.TechnicalUser.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               false,
				Usage:                  types.DevOps.String(),
				DataAssetsSent:         []string{"sourcecode"},
				DataAssetsReceived:     []string{},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
		}
		// The individual deployments
		for _, deployTargetID := range m.macroState["deploy-targets"] { // add a connection to each deployment target
			if m.containerTechUsed {
				if !dryRun {
					containerPlatform := modelInput.TechnicalAssets[m.macroState["container-platform"][0]+" Container Platform"]
					if containerPlatform.CommunicationLinks == nil {
						containerPlatform.CommunicationLinks = make(map[string]input.CommunicationLink)
					}
					containerPlatform.CommunicationLinks["Container Spawning ("+deployTargetID+")"] = input.CommunicationLink{
						Target:                 deployTargetID,
						Description:            "Container Spawning " + deployTargetID,
						Protocol:               types.ContainerSpawning.String(),
						Authentication:         types.NoneAuthentication.String(),
						Authorization:          types.NoneAuthorization.String(),
						Tags:                   []string{},
						VPN:                    false,
						IpFiltered:             false,
						Readonly:               false,
						Usage:                  types.DevOps.String(),
						DataAssetsSent:         []string{"deployment"},
						DataAssetsReceived:     nil,
						DiagramTweakWeight:     0,
						DiagramTweakConstraint: false,
					}
					modelInput.TechnicalAssets[m.macroState["container-platform"][0]+" Container Platform"] = containerPlatform
				}
			} else { // No Containers used
				if m.macroState["push-or-pull"][0] == pushOrPull[0] { // Push
					commLinks["Deployment Push ("+deployTargetID+")"] = input.CommunicationLink{
						Target:                 deployTargetID,
						Description:            "Deployment Push to " + deployTargetID,
						Protocol:               types.SSH.String(),
						Authentication:         types.ClientCertificate.String(),
						Authorization:          types.TechnicalUser.String(),
						Tags:                   []string{},
						VPN:                    false,
						IpFiltered:             false,
						Readonly:               false,
						Usage:                  types.DevOps.String(),
						DataAssetsSent:         []string{"deployment"},
						DataAssetsReceived:     nil,
						DiagramTweakWeight:     0,
						DiagramTweakConstraint: false,
					}
				} else { // Pull
					pullFromWhere := artifactRegistryID
					commLinkPull := input.CommunicationLink{
						Target:                 pullFromWhere,
						Description:            "Deployment Pull from " + deployTargetID,
						Protocol:               types.HTTPS.String(),
						Authentication:         types.Credentials.String(),
						Authorization:          types.TechnicalUser.String(),
						Tags:                   []string{},
						VPN:                    false,
						IpFiltered:             false,
						Readonly:               true,
						Usage:                  types.DevOps.String(),
						DataAssetsSent:         nil,
						DataAssetsReceived:     []string{"deployment"},
						DiagramTweakWeight:     0,
						DiagramTweakConstraint: false,
					}
					if !dryRun {
						// take care to lookup by title (as keyed in input YAML by title and only in parsed model representation by ID)
						titleOfTargetAsset := parsedModel.TechnicalAssets[deployTargetID].Title
						x := modelInput.TechnicalAssets[titleOfTargetAsset]
						if x.CommunicationLinks == nil {
							x.CommunicationLinks = make(map[string]input.CommunicationLink)
						}
						x.CommunicationLinks["Deployment Pull ("+deployTargetID+")"] = commLinkPull
						modelInput.TechnicalAssets[titleOfTargetAsset] = x
					}
				}
			}

			// don't forget to also add the "deployment" data asset as stored on the target
			targetAssetTitle := parsedModel.TechnicalAssets[deployTargetID].Title
			assetsStored := make([]string, 0)
			if modelInput.TechnicalAssets[targetAssetTitle].DataAssetsStored != nil {
				for _, val := range modelInput.TechnicalAssets[targetAssetTitle].DataAssetsStored {
					assetsStored = append(assetsStored, fmt.Sprintf("%v", val))
				}
			}
			mergedArrays := make([]string, 0)
			for _, val := range assetsStored {
				mergedArrays = append(mergedArrays, fmt.Sprintf("%v", val))
			}
			mergedArrays = append(mergedArrays, "deployment")
			if !dryRun {
				x := modelInput.TechnicalAssets[targetAssetTitle]
				x.DataAssetsStored = mergedArrays
				modelInput.TechnicalAssets[targetAssetTitle] = x
			}
		}

		techAsset := input.TechnicalAsset{
			ID:                      id,
			Description:             m.macroState["build-pipeline"][0] + " Build Pipeline",
			Type:                    types.Process.String(),
			Usage:                   types.DevOps.String(),
			UsedAsClientByHuman:     false,
			OutOfScope:              false,
			JustificationOutOfScope: "",
			Size:                    types.Service.String(),
			Technology:              types.BuildPipeline,
			Tags:                    []string{input.NormalizeTag(m.macroState["build-pipeline"][0])},
			Internet:                strings.EqualFold(m.macroState["internet"][0], "yes"),
			Machine:                 types.Virtual.String(),
			Encryption:              encryption,
			Owner:                   owner,
			Confidentiality:         types.Confidential.String(),
			Integrity:               types.Critical.String(),
			Availability:            types.Important.String(),
			JustificationCiaRating: "Build pipeline components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			MultiTenant:          strings.EqualFold(m.macroState["multi-tenant"][0], "yes"),
			Redundant:            false,
			CustomDevelopedParts: false,
			DataAssetsProcessed:  []string{"sourcecode", "deployment"},
			DataAssetsStored:     []string{"sourcecode", "deployment"},
			DataFormatsAccepted:  []string{"file"},
			CommunicationLinks:   commLinks,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.TechnicalAssets[m.macroState["build-pipeline"][0]+" Build Pipeline"] = techAsset
		}
	}

	id = artifactRegistryID
	if _, exists := parsedModel.TechnicalAssets[id]; !exists {
		serverSideTechAssets = append(serverSideTechAssets, id)
		encryption := types.NoneEncryption.String()
		if strings.EqualFold(m.macroState["encryption"][0], "yes") {
			encryption = types.Transparent.String()
		}
		techAsset := input.TechnicalAsset{
			ID:                      id,
			Description:             m.macroState["artifact-registry"][0] + " Artifact Registry",
			Type:                    types.Process.String(),
			Usage:                   types.DevOps.String(),
			UsedAsClientByHuman:     false,
			OutOfScope:              false,
			JustificationOutOfScope: "",
			Size:                    types.Service.String(),
			Technology:              types.ArtifactRegistry,
			Tags:                    []string{input.NormalizeTag(m.macroState["artifact-registry"][0])},
			Internet:                strings.EqualFold(m.macroState["internet"][0], "yes"),
			Machine:                 types.Virtual.String(),
			Encryption:              encryption,
			Owner:                   owner,
			Confidentiality:         types.Confidential.String(),
			Integrity:               types.Critical.String(),
			Availability:            types.Important.String(),
			JustificationCiaRating: "Artifact registry components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			MultiTenant:          strings.EqualFold(m.macroState["multi-tenant"][0], "yes"),
			Redundant:            false,
			CustomDevelopedParts: false,
			DataAssetsProcessed:  []string{"sourcecode", "deployment"},
			DataAssetsStored:     []string{"sourcecode", "deployment"},
			DataFormatsAccepted:  []string{"file"},
			CommunicationLinks:   nil,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.TechnicalAssets[m.macroState["artifact-registry"][0]+" Artifact Registry"] = techAsset
		}
	}

	if m.codeInspectionUsed {
		id = codeInspectionPlatformID
		if _, exists := parsedModel.TechnicalAssets[id]; !exists {
			serverSideTechAssets = append(serverSideTechAssets, id)
			encryption := types.NoneEncryption.String()
			if strings.EqualFold(m.macroState["encryption"][0], "yes") {
				encryption = types.Transparent.String()
			}
			techAsset := input.TechnicalAsset{
				ID:                      id,
				Description:             m.macroState[types.CodeInspectionPlatform][0] + " Code Inspection Platform",
				Type:                    types.Process.String(),
				Usage:                   types.DevOps.String(),
				UsedAsClientByHuman:     false,
				OutOfScope:              false,
				JustificationOutOfScope: "",
				Size:                    types.Service.String(),
				Technology:              types.CodeInspectionPlatform,
				Tags:                    []string{input.NormalizeTag(m.macroState[types.CodeInspectionPlatform][0])},
				Internet:                strings.EqualFold(m.macroState["internet"][0], "yes"),
				Machine:                 types.Virtual.String(),
				Encryption:              encryption,
				Owner:                   owner,
				Confidentiality:         types.Confidential.String(),
				Integrity:               types.Important.String(),
				Availability:            types.Operational.String(),
				JustificationCiaRating: "Sourcecode inspection platforms are rated at least 'important' in terms of integrity, because any " +
					"malicious modification of it might lead to vulnerabilities found by the scanner engine not being shown.",
				MultiTenant:          strings.EqualFold(m.macroState["multi-tenant"][0], "yes"),
				Redundant:            false,
				CustomDevelopedParts: false,
				DataAssetsProcessed:  []string{"sourcecode"},
				DataAssetsStored:     []string{"sourcecode"},
				DataFormatsAccepted:  []string{"file"},
				CommunicationLinks:   nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
			if !dryRun {
				modelInput.TechnicalAssets[m.macroState[types.CodeInspectionPlatform][0]+" Code Inspection Platform"] = techAsset
			}
		}
	}

	if m.withinTrustBoundary {
		if m.createNewTrustBoundary {
			trustBoundaryType := m.macroState["new-trust-boundary-type"][0]
			title := "DevOps Network"
			trustBoundary := input.TrustBoundary{
				ID:                    "devops-network",
				Description:           "DevOps Network",
				Type:                  trustBoundaryType,
				Tags:                  []string{},
				TechnicalAssetsInside: serverSideTechAssets,
				TrustBoundariesNested: nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding trust boundary: devops-network")
			if !dryRun {
				modelInput.TrustBoundaries[title] = trustBoundary
			}
		} else {
			existingTrustBoundaryToAddTo := m.macroState["selected-trust-boundary"][0]
			title := parsedModel.TrustBoundaries[existingTrustBoundaryToAddTo].Title
			assetsInside := make([]string, 0)
			if modelInput.TrustBoundaries[title].TechnicalAssetsInside != nil {
				values := modelInput.TrustBoundaries[title].TechnicalAssetsInside
				for _, val := range values {
					assetsInside = append(assetsInside, fmt.Sprintf("%v", val))
				}
			}
			mergedArrays := make([]string, 0)
			for _, val := range assetsInside {
				mergedArrays = append(mergedArrays, fmt.Sprintf("%v", val))
			}
			mergedArrays = append(mergedArrays, serverSideTechAssets...)
			*changeLogCollector = append(*changeLogCollector, "filling existing trust boundary: "+existingTrustBoundaryToAddTo)
			if !dryRun {
				if modelInput.TrustBoundaries == nil {
					modelInput.TrustBoundaries = make(map[string]input.TrustBoundary)
				}
				tb := modelInput.TrustBoundaries[title]
				tb.TechnicalAssetsInside = mergedArrays
				modelInput.TrustBoundaries[title] = tb
			}
		}
	}

	if m.containerTechUsed {
		// create shared runtime
		assetsRunning := make([]string, 0)
		assetsRunning = append(assetsRunning, m.macroState["deploy-targets"]...)
		title := m.macroState["container-platform"][0] + " Runtime"
		sharedRuntime := input.SharedRuntime{
			ID:                     containerSharedRuntimeID,
			Description:            title,
			Tags:                   []string{input.NormalizeTag(m.macroState["container-platform"][0])},
			TechnicalAssetsRunning: assetsRunning,
		}
		*changeLogCollector = append(*changeLogCollector, "adding shared runtime: "+containerSharedRuntimeID)
		if !dryRun {
			if modelInput.SharedRuntimes == nil {
				modelInput.SharedRuntimes = make(map[string]input.SharedRuntime)
			}
			modelInput.SharedRuntimes[title] = sharedRuntime
		}
	}

	return "Changeset valid", true, nil
}
