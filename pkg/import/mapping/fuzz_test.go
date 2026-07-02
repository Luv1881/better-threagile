package mapping

import "testing"

// FuzzParse feeds arbitrary bytes into Parse to make sure a malformed or
// adversarial mapping rules file is always rejected with an error rather
// than panicking. This mirrors the fuzz-test convention already used for
// the other importer parsers (drawio, threat-dragon, otm) — see
// improvement.md P9.
func FuzzParse(f *testing.F) {
	seeds := []string{
		``,
		`rules: []`,
		`rules:
  - match: { label: 'minio' }
    set: { technology: object-storage }`,
		`rules:
  - match: { edge: true, color: '#FF0000', line_style: dashed }
    set: { encryption: none, tags: [flagged-unencrypted] }`,
		`rules:
  - match: {}
    set: { technology: x }`,
		`rules: not-a-list`,
		`rules:
  - match: { label: '(' }
    set: { technology: x }`,
		`{`,
		`- - - -`,
		`rules: [{match: {label: "*"}, set: {technology: x}}]`,
		"rules:\n  - match:\n      label: \x00\x01\x02\n    set:\n      technology: x\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		// Parse must never panic on any input, valid or not.
		rs, err := Parse([]byte(data))
		if err != nil {
			return
		}
		// If it parsed successfully, Resolve must also never panic on any
		// element shape.
		if rs != nil {
			rs.Resolve(Element{Label: data, Edge: true, Color: data, LineStyle: data, FillColor: data})
		}
	})
}
