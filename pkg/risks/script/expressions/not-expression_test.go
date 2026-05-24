package expressions

import (
	"testing"

	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestNotExpression_simple_true_becomes_false(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("flag", common.SomeBoolValue(true, nil))

	expr, _, err := new(NotExpression).ParseBool(map[string]any{
		"true": "{flag}",
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	result, _, evalErr := expr.EvalBool(scope)
	if evalErr != nil {
		t.Fatalf("eval error: %v", evalErr)
	}
	if result.BoolValue() {
		t.Error("expected not(true) == false")
	}
}

func TestNotExpression_false_becomes_true(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("flag", common.SomeBoolValue(false, nil))

	expr, _, err := new(NotExpression).ParseBool(map[string]any{
		"true": "{flag}",
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	result, _, evalErr := expr.EvalBool(scope)
	if evalErr != nil {
		t.Fatalf("eval error: %v", evalErr)
	}
	if !result.BoolValue() {
		t.Error("expected not(false) == true")
	}
}

func TestNotExpression_wraps_contains(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("tags", common.SomeValue([]any{"has-csp", "prod"}, nil))

	// not: { contains: { item: missing-csp, in: "{tags}" } }
	// "missing-csp" is not in tags → contains=false → not=true
	expr, _, err := new(NotExpression).ParseBool(map[string]any{
		"contains": map[string]any{
			"item": "missing-csp",
			"in":   "{tags}",
		},
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	result, _, evalErr := expr.EvalBool(scope)
	if evalErr != nil {
		t.Fatalf("eval error: %v", evalErr)
	}
	if !result.BoolValue() {
		t.Error("expected not(contains missing-csp in [has-csp, prod]) == true")
	}
}
