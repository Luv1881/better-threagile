package compose

import (
	"strings"
	"testing"
)

func tagsOf(t *testing.T, yml string) map[string][]string {
	t.Helper()
	model, err := Import([]byte(yml), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, ta := range model.TechnicalAssets {
		out[ta.Title] = ta.Tags
	}
	return out
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func TestEnrichmentFlagsMisconfigurations(t *testing.T) {
	yml := `services:
  bad:
    image: app:latest
    privileged: true
    network_mode: host
    cap_add: [SYS_ADMIN]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  good:
    image: app:1.2.3
`
	tags := tagsOf(t, yml)
	for _, want := range []string{"review-privileged", "review-host-network", "review-added-capabilities", "review-docker-socket-mount", "review-mutable-image-tag"} {
		if !hasTag(tags["bad"], want) {
			t.Errorf("'bad' service should carry %q, got %v", want, tags["bad"])
		}
	}
	if len(tags["good"]) != 0 {
		t.Errorf("'good' service (pinned, unprivileged) should have no review tags, got %v", tags["good"])
	}
}

func TestUntaggedImageIsFlaggedDigestIsNot(t *testing.T) {
	flagged := tagsOf(t, "services:\n  a:\n    image: minio/minio\n")
	if !hasTag(flagged["a"], "review-mutable-image-tag") {
		t.Errorf("untagged image should be flagged, got %v", flagged["a"])
	}
	pinned := tagsOf(t, "services:\n  a:\n    image: minio/minio@sha256:abc123\n")
	if hasTag(pinned["a"], "review-mutable-image-tag") {
		t.Errorf("digest-pinned image should not be flagged, got %v", pinned["a"])
	}
}

func TestReviewTagsAreDeclaredAvailable(t *testing.T) {
	model, err := Import([]byte("services:\n  a:\n    image: app:latest\n    privileged: true\n"), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	avail := strings.Join(model.TagsAvailable, ",")
	for _, want := range []string{"review-privileged", "review-mutable-image-tag"} {
		if !strings.Contains(avail, want) {
			t.Errorf("tag %q must be declared in tags_available (%q)", want, avail)
		}
	}
}
