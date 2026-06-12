package types

type RiskTracking struct {
	SyntheticRiskId string     `json:"synthetic_risk_id,omitempty" yaml:"synthetic_risk_id,omitempty"`
	Justification   string     `json:"justification,omitempty" yaml:"justification,omitempty"`
	Ticket          string     `json:"ticket,omitempty" yaml:"ticket,omitempty"`
	CheckedBy       string     `json:"checked_by,omitempty" yaml:"checked_by,omitempty"`
	Status          RiskStatus `json:"status,omitempty" yaml:"status,omitempty"`
	Date            Date       `json:"date,omitempty" yaml:"date,omitempty"`
	// AcceptedUntil expires an accepted status; nil means no expiry.
	AcceptedUntil *Date `json:"accepted_until,omitempty" yaml:"accepted_until,omitempty"`
	// AcceptedBy records who signed off on the acceptance.
	AcceptedBy string `json:"accepted_by,omitempty" yaml:"accepted_by,omitempty"`
}

// IsAcceptanceExpired reports whether this tracking entry is an acceptance
// whose accepted_until date lies strictly before now (no expiry date = never expires).
func (what *RiskTracking) IsAcceptanceExpired(now Date) bool {
	return what.Status == Accepted && what.AcceptedUntil != nil && what.AcceptedUntil.Before(now.Time)
}
