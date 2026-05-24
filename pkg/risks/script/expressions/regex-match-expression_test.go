package expressions

import (
	"testing"

	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestRegexMatchExpression_matches(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("title", common.SomeStringValue("admin-panel", nil))

	expr, _, err := new(RegexMatchExpression).ParseBool(map[string]any{
		"pattern": "^admin",
		"value":   "{title}",
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	result, _, evalErr := expr.EvalBool(scope)
	if evalErr != nil {
		t.Fatalf("eval error: %v", evalErr)
	}
	if !result.BoolValue() {
		t.Error("expected regex match to be true")
	}
}

func TestRegexMatchExpression_no_match(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("title", common.SomeStringValue("user-service", nil))

	expr, _, err := new(RegexMatchExpression).ParseBool(map[string]any{
		"pattern": "^admin",
		"value":   "{title}",
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	result, _, evalErr := expr.EvalBool(scope)
	if evalErr != nil {
		t.Fatalf("eval error: %v", evalErr)
	}
	if result.BoolValue() {
		t.Error("expected regex match to be false")
	}
}

func TestRegexMatchExpression_invalid_pattern_returns_error(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("v", common.SomeStringValue("anything", nil))

	expr, _, err := new(RegexMatchExpression).ParseBool(map[string]any{
		"pattern": "[invalid",
		"value":   "{v}",
	})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	_, _, evalErr := expr.EvalBool(scope)
	if evalErr == nil {
		t.Error("expected eval error for invalid regex pattern")
	}
}
