package attack

import (
	"strings"
	"testing"
)

func TestEveryMappedD3FENDHasNameAndURL(t *testing.T) {
	for cat, ids := range CategoryD3FEND {
		for _, id := range ids {
			if !strings.HasPrefix(id, "D3-") {
				t.Errorf("category %s: %q is not a D3FEND id", cat, id)
			}
			if D3FENDName(id) == "" {
				t.Errorf("D3FEND %s (category %s) has no name", id, cat)
			}
			if url := D3FENDURL(id); !strings.HasPrefix(url, "https://d3fend.mitre.org/technique/d3f:") {
				t.Errorf("D3FEND %s has bad URL %q", id, url)
			}
		}
	}
}

func TestD3FENDUnknown(t *testing.T) {
	if D3FENDName("D3-NOPE") != "" || D3FENDURL("D3-NOPE") != "" {
		t.Fatal("unknown D3FEND id should yield empty name/url")
	}
}
