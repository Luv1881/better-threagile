package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/threagile/threagile/pkg/types"
)

func (adoc adocReport) technicalAssets(f *os.File) {
	writeLine(f, "= Identified Risks by Technical Asset")
	writeLine(f, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.CriticalSeverity)))+" are rated as critical*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.HighSeverity)))+" as high*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.ElevatedSeverity)))+" as elevated*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.MediumSeverity)))+" as medium*, "+
		"and *"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.LowSeverity)))+" as low*. "+
		"\n\nThese risks are distributed across *"+strconv.Itoa(len(adoc.model.InScopeTechnicalAssets()))+" in-scope technical assets*. ")
	writeLine(f, "The following sub-chapters of this section describe each identified risk grouped by technical asset. ") // TODO more explanation text
	writeLine(f, "The RAA value of a technical asset is the calculated \"Relative Attacker Attractiveness\" value in percent.")

	for _, technicalAsset := range sortedTechnicalAssetsByRiskSeverityAndTitle(adoc.model) {
		risksStr := adoc.model.GeneratedRisks(technicalAsset)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := riskSuffix(countStillAtRisk, len(risksStr))
		colorPrefix, colorSuffix := colorPrefixBySeverity(types.HighestSeverityStillAtRisk(risksStr), false)
		if technicalAsset.OutOfScope {
			colorPrefix = "[OutOfScope]#"
			suffix = "out-of-scope"
		} else {
			if len(types.ReduceToOnlyStillAtRisk(risksStr)) == 0 {
				colorPrefix = ""
				colorSuffix = ""
			}
		}

		// asset title
		title := colorPrefix + technicalAsset.Title + ": " + suffix + colorSuffix
		writeLine(f, "[["+technicalAsset.Id+"]]")
		writeLine(f, "== "+title)

		// asset description
		writeLine(f, "=== Description")
		writeLine(f, technicalAsset.Description)
		writeLine(f, "")

		// and more metadata of asset in tabular view
		writeLine(f, "=== Identified Risks of Asset")
		if len(risksStr) > 0 {
			writeLine(f, ":fn-risk-findings: footnote:riskfinding[Risk finding paragraphs are clickable and link to the corresponding chapter.]")
			for _, risk := range risksStr {
				colorPrefix, colorSuffix = colorPrefixBySeverity(types.HighestSeverityStillAtRisk(risksStr), false)
				if !risk.RiskStatus.IsStillAtRisk() {
					colorPrefix = ""
					colorSuffix = ""
				}
				writeLine(f, "\n==== "+colorPrefix+titleOfSeverity(risk.Severity)+colorSuffix+"\n")
				writeLine(f, colorPrefix+fixBasicHtml(risk.Title)+": Exploitation likelihood is _"+risk.ExploitationLikelihood.Title()+"_ with _"+risk.ExploitationImpact.Title()+"_ impact."+colorSuffix)
				writeLine(f, "")

				writeLine(f, "<<"+risk.CategoryId+",[SmallGrey]#"+risk.SyntheticId+"#>>")
				adoc.riskTrackingStatus(f, risk)
			}
		} else {
			text := "No risksStr were identified."
			if technicalAsset.OutOfScope {
				text = "Asset was defined as out-of-scope."
			}
			writeLine(f, "[GrayText]#"+text+"#")
		}

		// ASSET INFORMATION
		writeLine(f, "")
		writeLine(f, "<<<")
		writeLine(f, "")
		writeLine(f, "=== Asset Information")
		textRAA := fmt.Sprintf("%.0f", technicalAsset.RAA) + " %"
		if technicalAsset.OutOfScope {
			textRAA = "[GrayText]#out-of-scope#"
		}

		tagsUsedText := joinedOrNoneString(technicalAsset.Tags, "")
		dataAssetsProcessedText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsProcessedSorted(technicalAsset), "")
		dataAssetsStoredText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsStoredSorted(technicalAsset), "")
		formatsAcceptedText := dataFormatTitleJoinOrNone(technicalAsset.DataFormatsAcceptedSorted(), "[GrayText]#none of the special data formats accepted#")

		writeLine(f, `
[cols="h,1,h,1",frame=none,grid=none]
|===
| ID:             3+| `+technicalAsset.Id+`
| Type:             | `+technicalAsset.Type.String()+`| Usage: | `+technicalAsset.Usage.String()+`
| RAA:              | `+textRAA+`| Size: | `+technicalAsset.Size.String()+`
| Technology:       | `+technicalAsset.Technologies.String()+`| Tags: | `+tagsUsedText+`
| Internet:         | `+strconv.FormatBool(technicalAsset.Internet)+`| Machine: | `+technicalAsset.Machine.String()+`
| Encryption:       | `+technicalAsset.Encryption.String()+`| Multi-Tenant: | `+strconv.FormatBool(technicalAsset.MultiTenant)+`
| Redundant:        | `+strconv.FormatBool(technicalAsset.Redundant)+`| Custom-Developed: | `+strconv.FormatBool(technicalAsset.CustomDevelopedParts)+`
| Client by Human:  | `+strconv.FormatBool(technicalAsset.UsedAsClientByHuman)+`| Formats Accepted: | `+formatsAcceptedText+`
| Data Processed: 3+| `+dataAssetsProcessedText+`
| Data Stored:    3+| `+dataAssetsStoredText+`
|===
`)

		writeLine(f, "=== Asset Rating")
		writeLine(f, `
[cols="h,2",frame=none,grid=none]
|===
| Owner:             | `+technicalAsset.Owner+`
| Confidentiality:   | `+technicalAsset.Confidentiality.String()+`<<ref-confidentiality-values,*>>
| Integrity:         | `+technicalAsset.Integrity.String()+`<<ref-criticality-values,*>>
| Availability:      | `+technicalAsset.Availability.String()+`<<ref-criticality-values,*>>
| CIA-Justification: | `+technicalAsset.JustificationCiaRating)
		if technicalAsset.OutOfScope {
			writeLine(f, "| Asset Out-of-Scope Justification: 2+| "+technicalAsset.JustificationOutOfScope)
		}
		writeLine(f, "|===\n")

		if len(technicalAsset.CommunicationLinks) > 0 {
			writeLine(f, "=== Outgoing Communication Links: "+strconv.Itoa(len(technicalAsset.CommunicationLinks)))
			for _, outgoingCommLink := range technicalAsset.CommunicationLinksSorted() {
				writeLine(f, "==== "+outgoingCommLink.Title+" (outgoing)")
				writeLine(f, fixBasicHtml(outgoingCommLink.Description))

				tagsUsedText := joinedOrNoneString(outgoingCommLink.Tags, "")
				dataAssetsSentText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsSentSorted(outgoingCommLink), "")
				dataAssetsReceivedText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsReceivedSorted(outgoingCommLink), "")

				writeLine(f, `
[cols="h,1,h,1",frame=none,grid=none]
|===
| Target:         | <<`+outgoingCommLink.TargetId+`,`+adoc.model.TechnicalAssets[outgoingCommLink.TargetId].Title+`>>| Protocol:       | `+outgoingCommLink.Protocol.String()+`
| Encrypted:      | `+strconv.FormatBool(outgoingCommLink.Protocol.IsEncrypted())+`| Authentication: | `+outgoingCommLink.Authentication.String()+`
| Authorization:  | `+outgoingCommLink.Authorization.String()+`| Read-Only:      | `+strconv.FormatBool(outgoingCommLink.Readonly)+`
| Usage:          | `+outgoingCommLink.Usage.String()+`| Tags:           | `+tagsUsedText+`
| VPN:            | `+strconv.FormatBool(outgoingCommLink.VPN)+`| IP-Filtered:    | `+strconv.FormatBool(outgoingCommLink.IpFiltered)+`
| Data Sent:      | `+dataAssetsSentText+`| Data Received:  | `+dataAssetsReceivedText+`
|===
`)
			}
		}

		incomingCommLinks := adoc.model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		if len(incomingCommLinks) > 0 {
			writeLine(f, "=== Incoming Communication Links: "+strconv.Itoa(len(incomingCommLinks)))
			for _, incomingCommLink := range incomingCommLinks {
				writeLine(f, "==== "+incomingCommLink.Title+" (incoming)")
				writeLine(f, fixBasicHtml(incomingCommLink.Description))

				tagsUsedText := joinedOrNoneString(incomingCommLink.Tags, "")
				dataAssetsSentText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsSentSorted(incomingCommLink), "")
				dataAssetsReceivedText := dataAssetListTitleJoinOrNone(adoc.model.DataAssetsReceivedSorted(incomingCommLink), "")

				writeLine(f, `
[cols="h,1,h,1",frame=none,grid=none]
|===
| Source:         | <<`+incomingCommLink.SourceId+`,`+adoc.model.TechnicalAssets[incomingCommLink.SourceId].Title+`>>| Protocol:       | `+incomingCommLink.Protocol.String()+`
| Encrypted:      | `+strconv.FormatBool(incomingCommLink.Protocol.IsEncrypted())+`| Authentication: | `+incomingCommLink.Authentication.String()+`
| Authorization:  | `+incomingCommLink.Authorization.String()+`| Read-Only:      | `+strconv.FormatBool(incomingCommLink.Readonly)+`
| Usage:          | `+incomingCommLink.Usage.String()+`| Tags:           | `+tagsUsedText+`
| VPN:            | `+strconv.FormatBool(incomingCommLink.VPN)+`| IP-Filtered:    | `+strconv.FormatBool(incomingCommLink.IpFiltered)+`
| Data Sent:      | `+dataAssetsSentText+`| Data Received:  | `+dataAssetsReceivedText+`
|===
`)
			}
		}
	}
}

func (adoc adocReport) writeTechnicalAssets() error {
	filename := "180_TechnicalAssets.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.technicalAssets(f)
	return nil
}

func (adoc adocReport) dataAssets(f *os.File) {
	writeLine(f, "= Identified Data Breach Probabilities by Data Asset")
	writeLine(f, "In total *"+strconv.Itoa(totalRiskCount(adoc.model))+" potential risks* have been identified during the threat modeling process "+
		"of which "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.CriticalSeverity)))+" are rated as critical*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.HighSeverity)))+" as high*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.ElevatedSeverity)))+" as elevated*, "+
		"*"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.MediumSeverity)))+" as medium*, "+
		"and *"+strconv.Itoa(len(filteredBySeverity(adoc.model, types.LowSeverity)))+" as low*. "+
		"\n\nThese risks are distributed across *"+strconv.Itoa(len(adoc.model.DataAssets))+" data assets*. ")
	writeLine(f, "The following sub-chapters of this section describe the derived data breach probabilities grouped by data asset.") // TODO more explanation text
	writeLine(f, "")
	for _, dataAsset := range sortedDataAssetsByDataBreachProbabilityAndTitle(adoc.model) {

		dataBreachProbability := identifiedDataBreachProbabilityStillAtRisk(adoc.model, dataAsset)
		colorPrefix, colorSuffix := colorPrefixByDataBreachProbability(dataBreachProbability, false)
		if !isDataBreachPotentialStillAtRisk(adoc.model, dataAsset) {
			colorPrefix = ""
			colorSuffix = ""
		}
		risksStr := adoc.model.IdentifiedDataBreachProbabilityRisks(dataAsset)
		countStillAtRisk := len(types.ReduceToOnlyStillAtRisk(risksStr))
		suffix := riskSuffix(countStillAtRisk, len(risksStr))
		writeLine(f, "<<<")
		writeLine(f, "[[dataAsset:"+dataAsset.Id+"]]")
		writeLine(f, "== "+colorPrefix+dataAsset.Title+": "+suffix+colorSuffix)
		writeLine(f, fixBasicHtml(dataAsset.Description)+"\n\n")

		tagsUsedText := joinedOrNoneString(dataAsset.Tags, "")
		processedByText := technicalAssetTitleOrNone(adoc.model.ProcessedByTechnicalAssetsSorted(dataAsset), "")
		storedByText := technicalAssetTitleOrNone(adoc.model.StoredByTechnicalAssetsSorted(dataAsset), "")
		sentViaText := communicationLinkTitleOrNone(adoc.model.SentViaCommLinksSorted(dataAsset), "")
		receivedViaText := communicationLinkTitleOrNone(adoc.model.ReceivedViaCommLinksSorted(dataAsset), "")
		dataBreachRisksStillAtRisk := identifiedDataBreachProbabilityRisksStillAtRisk(adoc.model, dataAsset)
		sortByDataBreachProbability(dataBreachRisksStillAtRisk, adoc.model)
		dataBreachText := "This data asset has no data breach potential."
		if len(dataBreachRisksStillAtRisk) > 0 {
			riskRemainingStr := "risk"
			if countStillAtRisk > 1 {
				riskRemainingStr += "s"
			}
			dataBreachText = "This data asset has data breach potential because of " +
				"" + strconv.Itoa(countStillAtRisk) + " remaining " + riskRemainingStr + ":"
		}

		riskText := dataBreachProbability.String()
		if !isDataBreachPotentialStillAtRisk(adoc.model, dataAsset) {
			colorPrefix = ""
			colorSuffix = ""
			riskText = "none"
		}

		writeLine(f, `
[cols="h,1,h,1",frame=none,grid=none]
|===
| ID:                3+| `+dataAsset.Id+`
| Usage:               | `+dataAsset.Usage.String()+`| Quantity:          | `+dataAsset.Quantity.String()+`
| Tags:                | `+tagsUsedText+`| Origin:            | `+dataAsset.Origin+`
| Owner:               | `+dataAsset.Owner+`| Confidentiality:   | `+dataAsset.Confidentiality.String()+`<<ref-confidentiality-values,*>>
| Integrity:           | `+dataAsset.Integrity.String()+`<<ref-criticality-values,*>>| Availability:      | `+dataAsset.Availability.String()+`<<ref-criticality-values,*>>
| CIA-Justification: 3+| `+dataAsset.JustificationCiaRating+`
| Processed by:      3+| `+processedByText+`
| Stored by:         3+| `+storedByText+`
| Sent via:            | `+sentViaText+`| Received via:        | `+receivedViaText+`
| Data Breach:       3+| `+colorPrefix+riskText+colorSuffix+`
| Data Breach Risks: 3+| `+dataBreachText)

		if len(dataBreachRisksStillAtRisk) > 0 {
			for _, dataBreachRisk := range dataBreachRisksStillAtRisk {
				colorPrefix, colorSuffix := colorPrefixByDataBreachProbability(dataBreachRisk.DataBreachProbability, true)
				if !dataBreachRisk.RiskStatus.IsStillAtRisk() {
					colorPrefix = ""
				}

				txt := dataBreachRisk.DataBreachProbability.Title() + ": " + dataBreachRisk.SyntheticId
				writeLine(f, "|                    2+| <<"+dataBreachRisk.CategoryId+","+colorPrefix+txt+colorSuffix+">>")
			}
		}

		writeLine(f, `
|===
`)
	}
}

func (adoc adocReport) writeDataAssets() error {
	filename := "190_DataAssets.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.dataAssets(f)
	return nil
}
