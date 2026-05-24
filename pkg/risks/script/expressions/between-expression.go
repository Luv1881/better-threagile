package expressions

import (
	"fmt"

	"github.com/threagile/threagile/pkg/risks/script/common"
)

// BetweenExpression checks whether a value falls within an inclusive [min, max] range.
// All three operands are evaluated as decimals (string literals like "50" are auto-converted).
// Use as: <enum> to compare enum-typed values (e.g. confidentiality, criticality).
//
//	between:
//	  value: "{tech_asset.raa}"
//	  min: 50
//	  max: 100
//
//	between:
//	  value: "{data_asset.confidentiality}"
//	  min: confidential
//	  max: strictly-confidential
//	  as: confidentiality
type BetweenExpression struct {
	literal string
	value   common.ValueExpression
	min     common.ValueExpression
	max     common.ValueExpression
	as      string
}

func (what *BetweenExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	castScript, ok := script.(map[string]any)
	if !ok {
		return nil, script, fmt.Errorf("failed to parse between-expression: expected map, got %T", script)
	}

	for key, val := range castScript {
		switch key {
		case "value":
			expr, errScript, itemErr := new(ValueExpression).ParseValue(val)
			if itemErr != nil {
				return nil, errScript, fmt.Errorf("failed to parse %q of between-expression: %w", key, itemErr)
			}
			what.value = expr

		case "min":
			expr, errScript, itemErr := new(ValueExpression).ParseValue(val)
			if itemErr != nil {
				return nil, errScript, fmt.Errorf("failed to parse %q of between-expression: %w", key, itemErr)
			}
			what.min = expr

		case "max":
			expr, errScript, itemErr := new(ValueExpression).ParseValue(val)
			if itemErr != nil {
				return nil, errScript, fmt.Errorf("failed to parse %q of between-expression: %w", key, itemErr)
			}
			what.max = expr

		case common.As:
			s, ok2 := val.(string)
			if !ok2 {
				return nil, script, fmt.Errorf("between-expression: %q must be a string, got %T", key, val)
			}
			what.as = s

		default:
			return nil, script, fmt.Errorf("failed to parse between-expression: unexpected key %q", key)
		}
	}

	if what.value == nil {
		return nil, script, fmt.Errorf("between-expression requires a 'value' field")
	}
	if what.min == nil {
		return nil, script, fmt.Errorf("between-expression requires a 'min' field")
	}
	if what.max == nil {
		return nil, script, fmt.Errorf("between-expression requires a 'max' field")
	}

	return what, nil, nil
}

func (what *BetweenExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *BetweenExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	// When as: is set, compare via the cast path (enum int comparison).
	if len(what.as) > 0 {
		return what.evalBoolEnum(scope)
	}
	// Otherwise evaluate all operands as decimals so string literals like "50" auto-convert.
	return what.evalBoolDecimal(scope)
}

func (what *BetweenExpression) evalBoolDecimal(scope *common.Scope) (*common.BoolValue, string, error) {
	val, errLit, err := what.value.EvalDecimal(scope)
	if err != nil {
		return common.EmptyBoolValue(), errLit, fmt.Errorf("between-expression: failed to eval value: %w", err)
	}
	minVal, errLit, err := what.min.EvalDecimal(scope)
	if err != nil {
		return common.EmptyBoolValue(), errLit, fmt.Errorf("between-expression: failed to eval min: %w", err)
	}
	maxVal, errLit, err := what.max.EvalDecimal(scope)
	if err != nil {
		return common.EmptyBoolValue(), errLit, fmt.Errorf("between-expression: failed to eval max: %w", err)
	}

	// val >= min
	if val.DecimalValue().Cmp(minVal.DecimalValue()) < 0 {
		return common.SomeBoolValue(false, val.Event()), "", nil
	}
	// val <= max
	if val.DecimalValue().Cmp(maxVal.DecimalValue()) > 0 {
		return common.SomeBoolValue(false, val.Event()), "", nil
	}
	return common.SomeBoolValue(true, val.Event()), "", nil
}

func (what *BetweenExpression) evalBoolEnum(scope *common.Scope) (*common.BoolValue, string, error) {
	val, errLit, err := what.value.EvalAny(scope)
	if err != nil {
		return common.EmptyBoolValue(), errLit, fmt.Errorf("between-expression: failed to eval value: %w", err)
	}
	minVal, errLit, err := what.min.EvalAny(scope)
	if err != nil {
		return common.EmptyBoolValue(), errLit, fmt.Errorf("between-expression: failed to eval min: %w", err)
	}
	maxVal, errLit, err := what.max.EvalAny(scope)
	if err != nil {
		return common.EmptyBoolValue(), errLit, fmt.Errorf("between-expression: failed to eval max: %w", err)
	}

	// val >= min
	cmpMin, cmpErr := common.Compare(val, minVal, what.as)
	if cmpErr != nil {
		return common.EmptyBoolValue(), what.literal, fmt.Errorf("between-expression: min comparison failed: %w", cmpErr)
	}
	if !common.IsSame(cmpMin.Property) && !common.IsGreater(cmpMin.Property) {
		return common.SomeBoolValue(false, cmpMin), "", nil
	}
	// val <= max
	cmpMax, cmpErr := common.Compare(val, maxVal, what.as)
	if cmpErr != nil {
		return common.EmptyBoolValue(), what.literal, fmt.Errorf("between-expression: max comparison failed: %w", cmpErr)
	}
	if !common.IsSame(cmpMax.Property) && !common.IsLess(cmpMax.Property) {
		return common.SomeBoolValue(false, cmpMax), "", nil
	}
	return common.SomeBoolValue(true, cmpMax), "", nil
}

func (what *BetweenExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *BetweenExpression) Literal() string {
	return what.literal
}
