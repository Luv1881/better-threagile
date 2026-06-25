package attack

import "testing"

func TestEveryMappedCAPECHasName(t *testing.T) {
	for cat, ids := range CategoryCAPEC {
		for _, id := range ids {
			if CAPECName(id) == "" {
				t.Errorf("CAPEC %s (category %s) has no name in capecNames", id, cat)
			}
			if CAPECNumber(id) == "" {
				t.Errorf("CAPEC %s (category %s) has no numeric id", id, cat)
			}
		}
	}
}

func TestCAPECNumber(t *testing.T) {
	if got := CAPECNumber("CAPEC-66"); got != "66" {
		t.Fatalf("CAPECNumber = %q, want 66", got)
	}
	if CAPECNumber("T1190") != "" {
		t.Fatal("non-CAPEC id should yield empty number")
	}
}

func TestKnownCAPECMappings(t *testing.T) {
	cases := map[string]string{
		"sql-nosql-injection":         "CAPEC-66",
		"server-side-request-forgery": "CAPEC-664",
		"exposed-default-credentials": "CAPEC-70",
	}
	for cat, want := range cases {
		ids := CategoryCAPEC[cat]
		found := false
		for _, id := range ids {
			if id == want {
				found = true
			}
		}
		if !found {
			t.Errorf("category %s should map to %s, got %v", cat, want, ids)
		}
	}
}
