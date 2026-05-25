package types

// TrikeAction represents an operation in the Trike threat-modeling methodology.
type TrikeAction string

const (
	TrikeActionCreate  TrikeAction = "create"
	TrikeActionRead    TrikeAction = "read"
	TrikeActionUpdate  TrikeAction = "update"
	TrikeActionDelete  TrikeAction = "delete"
	TrikeActionExecute TrikeAction = "execute"
)

// TrikeActions returns all standard Trike actions.
func TrikeActions() []TrikeAction {
	return []TrikeAction{
		TrikeActionCreate,
		TrikeActionRead,
		TrikeActionUpdate,
		TrikeActionDelete,
		TrikeActionExecute,
	}
}

// TrikeMatrixCell represents one cell in the Trike action matrix.
// It specifies whether an actor performing an action on a technical asset
// is considered acceptable from an organisational risk perspective.
type TrikeMatrixCell struct {
	// ActorId references a TrikeActor.
	ActorId string `yaml:"actor_id" json:"actor_id"`
	// AssetId references a TechnicalAsset.
	AssetId string `yaml:"asset_id" json:"asset_id"`
	Action  TrikeAction `yaml:"action" json:"action"`
	// AcceptableRisk: true if the organisation has explicitly accepted this access pattern.
	AcceptableRisk bool `yaml:"acceptable_risk" json:"acceptable_risk"`
	// Justification explains why the access pattern is acceptable (or why not).
	Justification string `yaml:"justification,omitempty" json:"justification,omitempty"`
}
