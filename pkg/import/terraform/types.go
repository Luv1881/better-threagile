package terraform

// TFShow represents the top-level output of `terraform show -json`.
// Handles both state files (values.root_module) and plan files (planned_values.root_module).
type TFShow struct {
	FormatVersion string    `json:"format_version"`
	Values        *TFValues `json:"values,omitempty"`         // state
	PlannedValues *TFValues `json:"planned_values,omitempty"` // plan
}

type TFValues struct {
	RootModule TFModule `json:"root_module"`
}

type TFModule struct {
	Resources    []TFResource `json:"resources,omitempty"`
	ChildModules []TFModule   `json:"child_modules,omitempty"`
}

type TFResource struct {
	Address      string         `json:"address"`
	Type         string         `json:"type"`
	Name         string         `json:"name"`
	ProviderName string         `json:"provider_name"`
	Values       map[string]any `json:"values"`
}

// flatResources recursively collects all resources from a module tree.
func flatResources(m TFModule) []TFResource {
	out := make([]TFResource, 0, len(m.Resources))
	out = append(out, m.Resources...)
	for _, child := range m.ChildModules {
		out = append(out, flatResources(child)...)
	}
	return out
}
