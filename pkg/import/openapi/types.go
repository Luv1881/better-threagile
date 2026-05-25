package openapi

// OpenAPI3 is a minimal representation of an OpenAPI 3.x specification.
// Only fields relevant to threat modelling are parsed.
type OpenAPI3 struct {
	OpenAPI    string             `yaml:"openapi" json:"openapi"`
	Info       OAInfo             `yaml:"info" json:"info"`
	Servers    []OAServer         `yaml:"servers,omitempty" json:"servers,omitempty"`
	Paths      map[string]OAPath  `yaml:"paths,omitempty" json:"paths,omitempty"`
	Components OAComponents       `yaml:"components,omitempty" json:"components,omitempty"`
	Security   []OASecurityScheme `yaml:"security,omitempty" json:"security,omitempty"`
}

type OAInfo struct {
	Title       string `yaml:"title" json:"title"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Version     string `yaml:"version" json:"version"`
}

type OAServer struct {
	URL         string `yaml:"url" json:"url"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// OAPath maps HTTP verbs to operations.
type OAPath map[string]*OAOperation

// OAOperation is one HTTP operation on a path.
type OAOperation struct {
	OperationID string                     `yaml:"operationId,omitempty" json:"operationId,omitempty"`
	Summary     string                     `yaml:"summary,omitempty" json:"summary,omitempty"`
	Description string                     `yaml:"description,omitempty" json:"description,omitempty"`
	Tags        []string                   `yaml:"tags,omitempty" json:"tags,omitempty"`
	Security    []map[string][]string      `yaml:"security,omitempty" json:"security,omitempty"`
	RequestBody *OARequestBody             `yaml:"requestBody,omitempty" json:"requestBody,omitempty"`
	Responses   map[string]*OAResponse     `yaml:"responses,omitempty" json:"responses,omitempty"`
	Parameters  []OAParameter              `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

type OARequestBody struct {
	Required bool                      `yaml:"required,omitempty" json:"required,omitempty"`
	Content  map[string]OAMediaContent `yaml:"content,omitempty" json:"content,omitempty"`
}

type OAResponse struct {
	Description string                    `yaml:"description,omitempty" json:"description,omitempty"`
	Content     map[string]OAMediaContent `yaml:"content,omitempty" json:"content,omitempty"`
}

type OAMediaContent struct {
	Schema *OASchema `yaml:"schema,omitempty" json:"schema,omitempty"`
}

type OAParameter struct {
	Name     string    `yaml:"name" json:"name"`
	In       string    `yaml:"in" json:"in"` // path | query | header | cookie
	Required bool      `yaml:"required,omitempty" json:"required,omitempty"`
	Schema   *OASchema `yaml:"schema,omitempty" json:"schema,omitempty"`
}

type OASchema struct {
	Ref         string               `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	Type        string               `yaml:"type,omitempty" json:"type,omitempty"`
	Properties  map[string]*OASchema `yaml:"properties,omitempty" json:"properties,omitempty"`
	Items       *OASchema            `yaml:"items,omitempty" json:"items,omitempty"`
	Description string               `yaml:"description,omitempty" json:"description,omitempty"`
	Format      string               `yaml:"format,omitempty" json:"format,omitempty"`
}

type OAComponents struct {
	Schemas         map[string]*OASchema         `yaml:"schemas,omitempty" json:"schemas,omitempty"`
	SecuritySchemes map[string]OASecuritySchemeD `yaml:"securitySchemes,omitempty" json:"securitySchemes,omitempty"`
}

type OASecuritySchemeD struct {
	Type   string `yaml:"type,omitempty" json:"type,omitempty"`   // apiKey | http | oauth2 | openIdConnect
	Scheme string `yaml:"scheme,omitempty" json:"scheme,omitempty"` // bearer | basic
	In     string `yaml:"in,omitempty" json:"in,omitempty"`       // header | query | cookie
}

// Stub needed for top-level security field (list of scheme-name → scopes maps)
type OASecurityScheme map[string][]string
