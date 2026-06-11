package report

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (adoc adocReport) securityRequirements(f *os.File) int {
	writeLine(f, "= Security Requirements")
	writeLine(f, "This chapter lists the custom security requirements which have been defined for the modeled target.")

	writeLine(f, "\n")
	requirements := sortedKeysOfSecurityRequirements(adoc.model)
	for _, title := range requirements {
		description := adoc.model.SecurityRequirements[title]
		writeLine(f, title+"::")
		writeLine(f, "  "+description)
		writeLine(f, "")
	}
	writeLine(f, "\n\n")
	writeLine(f, "_This list is not complete and regulatory or law relevant security requirements have to be "+
		"taken into account as well. Also custom individual security requirements might exist for the project._")
	return len(requirements)
}

func (adoc adocReport) writeSecurityRequirements() error {
	filename := "070_SecurityRequirements.adoc"
	sr, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = sr.Close() }()
	if err != nil {
		return err
	}

	nRequirements := adoc.securityRequirements(sr)
	if nRequirements > 0 || !adoc.hideEmptyChapter {
		adoc.writeMainLine("<<<")
		adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")
	}
	return nil
}

func (adoc adocReport) abuseCases(f *os.File) int {
	writeLine(f, "= Abuse Cases")
	writeLine(f, "This chapter lists the custom abuse cases which have been defined for the modeled target.")
	writeLine(f, "\n")
	cases := sortedKeysOfAbuseCases(adoc.model)
	for _, title := range cases {
		description := adoc.model.AbuseCases[title]
		writeLine(f, title+"::")
		writeLine(f, "  "+description)
		writeLine(f, "")
	}
	writeLine(f, "\n\n")
	writeLine(f, "_This list is not complete and regulatory or law relevant abuse cases have to be "+
		"taken into account as well. Also custom individual abuse cases might exist for the project._")
	return len(cases)
}

func (adoc adocReport) writeAbuseCases() error {
	filename := "080_AbuseCases.adoc"
	ac, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = ac.Close() }()
	if err != nil {
		return err
	}

	nCases := adoc.abuseCases(ac)
	if nCases > 0 || !adoc.hideEmptyChapter {
		adoc.writeMainLine("<<<")
		adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")
	}
	return nil
}

func (adoc adocReport) questions(f *os.File) int {
	questionStr := "Question"
	count := len(adoc.model.Questions)
	if count > 1 {
		questionStr += "s"
	}
	colorPrefix := ""
	colorSuffix := ""
	if questionsUnanswered(adoc.model) > 0 {
		colorPrefix = "[ModelFailure]#"
		colorSuffix = "#"
	}
	writeLine(f, "= "+colorPrefix+"Questions: "+strconv.Itoa(questionsUnanswered(adoc.model))+" / "+strconv.Itoa(count)+" "+questionStr+colorSuffix)
	writeLine(f, "")
	writeLine(f, "This chapter lists custom questions that arose during the threat modeling process.")
	writeLine(f, "")

	if len(adoc.model.Questions) == 0 {
		writeLine(f, "")
		writeLine(f, "[GreyText]#No custom questions arose during the threat modeling process.#")
	}
	writeLine(f, "")

	questions := sortedKeysOfQuestions(adoc.model)
	for _, question := range questions {
		answer := adoc.model.Questions[question]
		if len(strings.TrimSpace(answer)) > 0 {
			writeLine(f, "*"+question+"*::")
			writeLine(f, "_"+strings.TrimSpace(answer)+"_")
		} else {
			writeLine(f, "*[ModelFailure]#"+question+"#*::")
			writeLine(f, "[GreyText]#_- answer pending -_#")
		}
		writeLine(f, "")
	}
	return len(questions)
}

func (adoc adocReport) writeQuestions() error {
	filename := "160_Questions.adoc"
	f, err := os.Create(filepath.Join(adoc.targetDirectory, filename))
	defer func() { _ = f.Close() }()
	if err != nil {
		return err
	}

	nQuestions := adoc.questions(f)
	if nQuestions > 0 || !adoc.hideEmptyChapter {
		adoc.writeMainLine("<<<")
		adoc.writeMainLine("include::" + filename + "[leveloffset=+1]")
	}

	return nil
}
