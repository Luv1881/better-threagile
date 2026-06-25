package threatdragon

// tdModel is the subset of an OWASP Threat Dragon v2 model file we read.
type tdModel struct {
	Version string    `json:"version"`
	Summary tdSummary `json:"summary"`
	Detail  tdDetail  `json:"detail"`
}

type tdSummary struct {
	Title       string `json:"title"`
	Owner       string `json:"owner"`
	Description string `json:"description"`
}

type tdDetail struct {
	Diagrams []tdDiagram `json:"diagrams"`
}

type tdDiagram struct {
	ID    int      `json:"id"`
	Title string   `json:"title"`
	Cells []tdCell `json:"cells"`
}

// tdCell is a node or an edge. Edges carry Source/Target; nodes carry Position/Size.
type tdCell struct {
	Shape    string      `json:"shape"`
	ID       string      `json:"id"`
	Position *tdPoint    `json:"position"`
	Size     *tdSize     `json:"size"`
	Source   *tdEndpoint `json:"source"`
	Target   *tdEndpoint `json:"target"`
	Data     tdData      `json:"data"`
}

type tdPoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type tdSize struct {
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type tdEndpoint struct {
	Cell string `json:"cell"`
	Port string `json:"port"`
}

type tdData struct {
	Type              string `json:"type"` // tm.Actor / tm.Process / tm.Store / tm.BoundaryBox / tm.Flow
	Name              string `json:"name"`
	Description       string `json:"description"`
	OutOfScope        bool   `json:"outOfScope"`
	IsTrustBoundary   bool   `json:"isTrustBoundary"`
	IsEncrypted       bool   `json:"isEncrypted"`
	IsPublicNetwork   bool   `json:"isPublicNetwork"`
	Protocol          string `json:"protocol"`
	IsWebApplication  bool   `json:"isWebApplication"`
	StoresCredentials bool   `json:"storesCredentials"`
}
