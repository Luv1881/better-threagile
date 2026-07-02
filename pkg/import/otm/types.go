package otm

// The Open Threat Model (OTM) JSON structures below are intentionally
// tolerant of missing/extra fields (IriusRisk's OTM spec is still evolving
// and producers vary); every field is optional from this importer's point of
// view and absence is handled with sane defaults rather than an error.

type otmDocument struct {
	OtmVersion string     `json:"otmVersion"`
	Project    otmProject `json:"project"`
	TrustZones []otmZone  `json:"trustZones"`
	Components []otmComp  `json:"components"`
	Dataflows  []otmFlow  `json:"dataflows"`
	Assets     []otmAsset `json:"assets"`
}

type otmProject struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type otmParent struct {
	TrustZone string `json:"trustZone"`
	Component string `json:"component"`
}

type otmRisk struct {
	TrustRating     *int `json:"trustRating"`
	Confidentiality *int `json:"confidentiality"`
	Integrity       *int `json:"integrity"`
	Availability    *int `json:"availability"`
}

type otmZone struct {
	Id          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Risk        otmRisk    `json:"risk"`
	Parent      *otmParent `json:"parent"`
}

type otmComp struct {
	Id          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Type        string     `json:"type"`
	Tags        []string   `json:"tags"`
	Parent      *otmParent `json:"parent"`
}

type otmFlow struct {
	Id            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Source        string   `json:"source"`
	Destination   string   `json:"destination"`
	Bidirectional bool     `json:"bidirectional"`
	Tags          []string `json:"tags"`
}

type otmAsset struct {
	Id          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Risk        otmRisk  `json:"risk"`
}
