package report

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/threagile/threagile/pkg/types"
)

func (adoc adocReport) tagListing(f *os.File) {
	writeLine(f, "= Tag Listing")

	writeLine(f, "This chapter lists what tags are used by which elements.")
	writeLine(f, "\n")
	sorted := adoc.model.TagsAvailable
	sort.Strings(sorted)
	for _, tag := range sorted {
		description := "" // TODO: add some separation texts to distinguish between technical assets and data assets etc. for example?
		for _, techAsset := range sortedTechnicalAssetsByTitle(adoc.model) {
			if contains(techAsset.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += techAsset.Title
			}
			for _, commLink := range techAsset.CommunicationLinksSorted() {
				if contains(commLink.Tags, tag) {
					if len(description) > 0 {
						description += ", "
					}
					description += commLink.Title
				}
			}
		}
		for _, dataAsset := range sortedDataAssetsByTitle(adoc.model) {
			if contains(dataAsset.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += dataAsset.Title
			}
		}
		for _, trustBoundary := range sortedTrustBoundariesByTitle(adoc.model) {
			if contains(trustBoundary.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += trustBoundary.Title
			}
		}
		for _, sharedRuntime := range sortedSharedRuntimesByTitle(adoc.model) {
			if contains(sharedRuntime.Tags, tag) {
				if len(description) > 0 {
					description += ", "
				}
				description += sharedRuntime.Title
			}
		}
		if len(description) > 0 {
			writeLine(f, tag+"::")
			writeLine(f, "  "+description)
			writeLine(f, "")
		}
	}
}

func (adoc adocReport) writeTagListing() error {
	filename := "090_TagListing.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.tagListing(f)
	return nil
}

func (adoc adocReport) stride(f *os.File) {
	writeLine(f, "= STRIDE Classification of Identified Risks")
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")

	risksSTRIDESpoofing := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Spoofing)
	risksSTRIDETampering := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Tampering)
	risksSTRIDERepudiation := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Repudiation)
	risksSTRIDEInformationDisclosure := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.InformationDisclosure)
	risksSTRIDEDenialOfService := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.DenialOfService)
	risksSTRIDEElevationOfPrivilege := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.ElevationOfPrivilege)

	countSTRIDESpoofing := countRisks(risksSTRIDESpoofing)
	countSTRIDETampering := countRisks(risksSTRIDETampering)
	countSTRIDERepudiation := countRisks(risksSTRIDERepudiation)
	countSTRIDEInformationDisclosure := countRisks(risksSTRIDEInformationDisclosure)
	countSTRIDEDenialOfService := countRisks(risksSTRIDEDenialOfService)
	countSTRIDEElevationOfPrivilege := countRisks(risksSTRIDEElevationOfPrivilege)

	writeLine(f, "This chapter clusters and classifies the risks by STRIDE categories: "+
		"In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which *"+strconv.Itoa(countSTRIDESpoofing)+" in the "+types.Spoofing.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDETampering)+" in the "+types.Tampering.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDERepudiation)+" in the "+types.Repudiation.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDEInformationDisclosure)+" in the "+types.InformationDisclosure.Title()+"* category, "+
		"*"+strconv.Itoa(countSTRIDEDenialOfService)+" in the "+types.DenialOfService.Title()+"* category, "+
		"and *"+strconv.Itoa(countSTRIDEElevationOfPrivilege)+" in the "+types.ElevationOfPrivilege.Title()+"* category.{fn-risk-findings}")
	writeLine(f, "")

	reverseRiskSeverity := []types.RiskSeverity{
		types.CriticalSeverity,
		types.HighSeverity,
		types.ElevatedSeverity,
		types.MediumSeverity,
		types.LowSeverity,
	}
	strides := []types.STRIDE{
		types.Spoofing,
		types.Tampering,
		types.Repudiation,
		types.InformationDisclosure,
		types.DenialOfService,
		types.ElevationOfPrivilege,
	}

	for _, strideValue := range strides {
		writeLine(f, "== "+strideValue.Title())
		risksSTRIDE := reduceToSTRIDERisk(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), strideValue)
		if len(risksSTRIDE) > 0 {
			for _, critValue := range reverseRiskSeverity {
				adoc.addCategories(f, risksSTRIDE, true, critValue, true, true)
			}
		} else {
			writeLine(f, "No risk identified.")
		}
		writeLine(f, "")
	}
}

func (adoc adocReport) writeSTRIDE() error {
	filename := "100_STRIDE.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.stride(f)
	return nil
}

func (adoc adocReport) assignmentByFunction(f *os.File) {
	writeLine(f, "= Assignment by Function")
	writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
	writeLine(f, "")

	risksBusinessSideFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.BusinessSide)
	risksArchitectureFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Architecture)
	risksDevelopmentFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Development)
	risksOperationFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategory, types.Operations)

	countBusinessSideFunction := countRisks(risksBusinessSideFunction)
	countArchitectureFunction := countRisks(risksArchitectureFunction)
	countDevelopmentFunction := countRisks(risksDevelopmentFunction)
	countOperationFunction := countRisks(risksOperationFunction)
	writeLine(f, "This chapter clusters and assigns the risks by functions which are most likely able to "+
		"check and mitigate them: "+
		"In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which *"+strconv.Itoa(countBusinessSideFunction)+" should be checked by "+types.BusinessSide.Title()+"*, "+
		"*"+strconv.Itoa(countArchitectureFunction)+" should be checked by "+types.Architecture.Title()+"*, "+
		"*"+strconv.Itoa(countDevelopmentFunction)+" should be checked by "+types.Development.Title()+"*, "+
		"and *"+strconv.Itoa(countOperationFunction)+" should be checked by "+types.Operations.Title()+"*.{fn-risk-findings}")
	writeLine(f, "")

	riskFunctionValues := []types.RiskFunction{
		types.BusinessSide,
		types.Architecture,
		types.Development,
		types.Operations,
	}
	reverseRiskSeverity := []types.RiskSeverity{
		types.CriticalSeverity,
		types.HighSeverity,
		types.ElevatedSeverity,
		types.MediumSeverity,
		types.LowSeverity,
	}

	for _, riskFunctionValue := range riskFunctionValues {
		writeLine(f, "== "+riskFunctionValue.Title())
		risksFunction := reduceToFunctionRisk(adoc.model, adoc.model.GeneratedRisksByCategoryWithCurrentStatus(), riskFunctionValue)
		for _, critValue := range reverseRiskSeverity {
			adoc.addCategories(f, risksFunction, true, critValue, true, false)
		}
		writeLine(f, "")
	}
}

func (adoc adocReport) writeAssignmentByFunction() error {
	filename := "110_AssignmentByFunction.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.assignmentByFunction(f)
	return nil
}
