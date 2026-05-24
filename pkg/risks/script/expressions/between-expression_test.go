package expressions

import (
	"testing"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

func TestBetweenExpression_value_inside_range(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("raa", common.SomeDecimalValue(decimal.NewFromInt(75), nil))

	expr, _, err := new(BetweenExpression).ParseBool(map[string]any{
		"value": "{raa}",
		"min":   "50",
		"max":   "100",
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	result, _, evalErr := expr.EvalBool(scope)
	if evalErr != nil {
		t.Fatalf("eval error: %v", evalErr)
	}
	if !result.BoolValue() {
		t.Error("expected 75 between 50 and 100 == true")
	}
}

func TestBetweenExpression_value_below_min(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("raa", common.SomeDecimalValue(decimal.NewFromInt(20), nil))

	expr, _, err := new(BetweenExpression).ParseBool(map[string]any{
		"value": "{raa}",
		"min":   "50",
		"max":   "100",
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	result, _, evalErr := expr.EvalBool(scope)
	if evalErr != nil {
		t.Fatalf("eval error: %v", evalErr)
	}
	if result.BoolValue() {
		t.Error("expected 20 between 50 and 100 == false")
	}
}

func TestBetweenExpression_value_above_max(t *testing.T) {
	scope := new(common.Scope)
	_ = scope.Init(nil, nil)
	scope.Set("raa", common.SomeDecimalValue(decimal.NewFromInt(150), nil))

	expr, _, err := new(BetweenExpression).ParseBool(map[string]any{
		"value": "{raa}",
		"min":   "50",
		"max":   "100",
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	result, _, evalErr := expr.EvalBool(scope)
	if evalErr != nil {
		t.Fatalf("eval error: %v", evalErr)
	}
	if result.BoolValue() {
		t.Error("expected 150 between 50 and 100 == false")
	}
}

func TestBetweenExpression_boundary_values_are_inclusive(t *testing.T) {
	for _, v := range []int64{50, 100} {
		scope := new(common.Scope)
		_ = scope.Init(nil, nil)
		scope.Set("raa", common.SomeDecimalValue(decimal.NewFromInt(v), nil))

		expr, _, err := new(BetweenExpression).ParseBool(map[string]any{
			"value": "{raa}",
			"min":   "50",
			"max":   "100",
		})
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		result, _, evalErr := expr.EvalBool(scope)
		if evalErr != nil {
			t.Fatalf("eval error for v=%d: %v", v, evalErr)
		}
		if !result.BoolValue() {
			t.Errorf("expected boundary value %d to be inclusive (between 50 and 100)", v)
		}
	}
}
