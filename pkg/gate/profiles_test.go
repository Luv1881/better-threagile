package gate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every bundled profile must parse through the SAME strict (KnownFields) loader
// the gate uses, so a typo in a template can never ship as a silently-ignored
// (and therefore non-enforcing) gate rule.
func TestBundledProfilesAreValidPolicies(t *testing.T) {
	for _, name := range ProfileNames() {
		data, err := ProfileTemplate(name)
		if err != nil {
			t.Fatalf("ProfileTemplate(%q): %v", name, err)
		}
		var p Policy
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&p); err != nil {
			t.Errorf("profile %q is not a valid policy: %v", name, err)
		}
		if strings.TrimSpace(p.Name) == "" {
			t.Errorf("profile %q has no name", name)
		}
	}
}

// LoadPolicy must accept a profile written to disk (round-trip through the CLI path).
func TestProfileRoundTripsThroughLoadPolicy(t *testing.T) {
	for _, name := range ProfileNames() {
		data, err := ProfileTemplate(name)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), name+".yaml")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(path); err != nil {
			t.Errorf("LoadPolicy(%q profile): %v", name, err)
		}
	}
}

func TestProfilesAreOrderedLooseToStrict(t *testing.T) {
	// The cap count should be non-decreasing in strictness: each profile caps at
	// least as many severities as the looser one before it.
	prev := -1
	for _, name := range ProfileNames() {
		data, _ := ProfileTemplate(name)
		var p Policy
		_ = yaml.Unmarshal(data, &p)
		caps := len(p.MaxSeverityCounts)
		if caps < prev {
			t.Errorf("profile %q caps %d severities, fewer than the looser profile (%d)", name, caps, prev)
		}
		prev = caps
	}
}

// profileOrder and profileDescriptions must stay in lockstep: a profile present
// in one but not the other would be either hidden or undescribed.
func TestProfileRegistriesMatch(t *testing.T) {
	if len(profileOrder) != len(profileDescriptions) {
		t.Fatalf("profileOrder (%d) and profileDescriptions (%d) differ in size", len(profileOrder), len(profileDescriptions))
	}
	for _, name := range profileOrder {
		if _, ok := profileDescriptions[name]; !ok {
			t.Errorf("profile %q in profileOrder has no description", name)
		}
	}
}

func TestUnknownProfileRejected(t *testing.T) {
	_, err := ProfileTemplate("nope")
	if err == nil || !strings.Contains(err.Error(), "unknown policy profile") {
		t.Fatalf("expected unknown-profile error, got %v", err)
	}
}

// The embedded template files and the profile registry must stay in sync.
func TestEveryTemplateFileIsRegistered(t *testing.T) {
	files := allProfileFiles()
	if len(files) != len(ProfileNames()) {
		t.Fatalf("template files (%v) and registered profiles (%v) differ in count", files, ProfileNames())
	}
	for _, name := range ProfileNames() {
		want := name + ".yaml"
		found := false
		for _, f := range files {
			if f == want {
				found = true
			}
		}
		if !found {
			t.Errorf("registered profile %q has no template file %q", name, want)
		}
	}
}
