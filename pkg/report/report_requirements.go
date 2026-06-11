package report

import (
	"sort"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

func (r *pdfReporter) createSecurityRequirements(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "Security Requirements"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{security-requirements}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists the custom security requirements which have been defined for the modeled target.")
	r.pdfColorBlack()
	for _, title := range sortedKeysOfSecurityRequirements(parsedModel) {
		description := parsedModel.SecurityRequirements[title]
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		html.Write(5, "<b>"+uni(title)+"</b><br>")
		html.Write(5, uni(description))
	}
	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	html.Write(5, "<i>This list is not complete and regulatory or law relevant security requirements have to be "+
		"taken into account as well. Also custom individual security requirements might exist for the project.</i>")
}

func sortedKeysOfSecurityRequirements(parsedModel *types.Model) []string {
	keys := make([]string, 0)
	for k := range parsedModel.SecurityRequirements {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *pdfReporter) createAbuseCases(parsedModel *types.Model) {
	r.pdf.SetTextColor(0, 0, 0)
	chapTitle := "Abuse Cases"
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{abuse-cases}")
	r.currentChapterTitleBreadcrumb = chapTitle

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists the custom abuse cases which have been defined for the modeled target.")
	r.pdfColorBlack()
	for _, title := range sortedKeysOfAbuseCases(parsedModel) {
		description := parsedModel.AbuseCases[title]
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		html.Write(5, "<b>"+title+"</b><br>")
		html.Write(5, description)
	}
	if r.pdf.GetY() > 250 {
		r.pageBreak()
		r.pdf.SetY(36)
	} else {
		html.Write(5, "<br><br><br>")
	}
	html.Write(5, "<i>This list is not complete and regulatory or law relevant abuse cases have to be "+
		"taken into account as well. Also custom individual abuse cases might exist for the project.</i>")
}

func sortedKeysOfAbuseCases(parsedModel *types.Model) []string {
	keys := make([]string, 0)
	for k := range parsedModel.AbuseCases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *pdfReporter) createQuestions(parsedModel *types.Model) {
	uni := r.pdf.UnicodeTranslatorFromDescriptor("")
	r.pdf.SetTextColor(0, 0, 0)
	questions := "Questions"
	count := len(parsedModel.Questions)
	if count == 1 {
		questions = "Question"
	}
	if questionsUnanswered(parsedModel) > 0 {
		colorModelFailure(r.pdf)
	}
	chapTitle := "Questions: " + strconv.Itoa(questionsUnanswered(parsedModel)) + " / " + strconv.Itoa(count) + " " + questions
	r.addHeadline(chapTitle, false)
	r.defineLinkTarget("{questions}")
	r.currentChapterTitleBreadcrumb = chapTitle
	r.pdfColorBlack()

	html := r.pdf.HTMLBasicNew()
	html.Write(5, "This chapter lists custom questions that arose during the threat modeling process.")

	if len(parsedModel.Questions) == 0 {
		r.pdfColorLightGray()
		html.Write(5, "<br><br><br>")
		html.Write(5, "No custom questions arose during the threat modeling process.")
	}
	r.pdfColorBlack()
	for _, question := range sortedKeysOfQuestions(parsedModel) {
		answer := parsedModel.Questions[question]
		if r.pdf.GetY() > 250 {
			r.pageBreak()
			r.pdf.SetY(36)
		} else {
			html.Write(5, "<br><br><br>")
		}
		r.pdfColorBlack()
		if len(strings.TrimSpace(answer)) > 0 {
			html.Write(5, "<b>"+uni(question)+"</b><br>")
			html.Write(5, "<i>"+uni(strings.TrimSpace(answer))+"</i>")
		} else {
			colorModelFailure(r.pdf)
			html.Write(5, "<b>"+uni(question)+"</b><br>")
			r.pdfColorLightGray()
			html.Write(5, "<i>- answer pending -</i>")
			r.pdfColorBlack()
		}
	}
}

func questionsUnanswered(parsedModel *types.Model) int {
	result := 0
	for _, answer := range parsedModel.Questions {
		if len(strings.TrimSpace(answer)) == 0 {
			result++
		}
	}
	return result
}
