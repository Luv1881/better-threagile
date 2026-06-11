package report

import (
	"os"
	"path/filepath"
	"strconv"
)

func (adoc adocReport) trustBoundaries(f *os.File) {
	writeLine(f, "= Trust Boundaries")

	word := "has"
	if len(adoc.model.TrustBoundaries) > 1 {
		word = "have"
	}
	writeLine(f, "In total *"+strconv.Itoa(len(adoc.model.TrustBoundaries))+" trust boundaries* "+word+" been "+
		"modeled during the threat modeling process.")
	writeLine(f, "")
	for _, trustBoundary := range sortedTrustBoundariesByTitle(adoc.model) {
		colorPrefix := "[.Twilight]#"
		colorSuffix := "#"
		if !trustBoundary.Type.IsNetworkBoundary() {
			colorPrefix = "[.LightGreyText]#"
		}
		writeLine(f, "[["+trustBoundary.Id+"]]")
		writeLine(f, "== "+colorPrefix+trustBoundary.Title+colorSuffix)
		writeLine(f, colorPrefix+trustBoundary.Description+colorSuffix)
		writeLine(f, "")

		tagsUsedText := joinedOrNoneString(trustBoundary.Tags, "")
		assetsInsideText := joinedOrNoneString(trustBoundary.TechnicalAssetsInside, "")
		boundariesNestedText := joinedOrNoneString(trustBoundary.TrustBoundariesNested, "")

		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| ID:                | `+trustBoundary.Id+`
| Type:              | `+colorPrefix+trustBoundary.Type.String()+colorSuffix+`
| Tags:              | `+tagsUsedText+`
| Assets inside:     | `+assetsInsideText+`
| Boundaries nested: | `+boundariesNestedText+`
|===
`)
	}

}

func (adoc adocReport) writeTrustBoundaries() error {
	filename := "200_TrustBoundaries.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.trustBoundaries(f)
	return nil
}

func (adoc adocReport) sharedRuntimes(f *os.File) {
	writeLine(f, "= Shared Runtimes")
	word, runtime := "has", "runtime"
	if len(adoc.model.SharedRuntimes) > 1 {
		word, runtime = "have", "runtimes"
	}
	writeLine(f, "In total *"+strconv.Itoa(len(adoc.model.SharedRuntimes))+" shared "+runtime+"* "+word+" been "+
		"modeled during the threat modeling process.")
	writeLine(f, "")
	for _, sharedRuntime := range sortedSharedRuntimesByTitle(adoc.model) {
		writeLine(f, "[["+sharedRuntime.Id+"]]")
		writeLine(f, "== "+sharedRuntime.Title)
		writeLine(f, sharedRuntime.Description)
		writeLine(f, "")

		tagsUsedText := joinedOrNoneString(sharedRuntime.Tags, "")
		assetsRunningText := joinedOrNoneString(sharedRuntime.TechnicalAssetsRunning, "")
		writeLine(f, `
[cols="h,1",frame=none,grid=none]
|===
| ID:             | `+sharedRuntime.Id+`
| Tags:           | `+tagsUsedText+`
| Assets running: | `+assetsRunningText+`
|===
`)
	}
}

func (adoc adocReport) writeSharedRuntimes() error {
	filename := "210_SharedRuntimes.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}
	adoc.writeMainLine("<<<")
	adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")

	adoc.sharedRuntimes(f)
	return nil
}
