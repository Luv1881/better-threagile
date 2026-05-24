package expressions

import (
	"fmt"
	"github.com/threagile/threagile/pkg/risks/script/common"
)

// NotExpression is the logical NOT of a bool expression.
// It is a more readable alias for the existing false: operator:
//
//	not:
//	  contains:
//	    item: has-csp
//	    in: "{tech_asset.tags}"
type NotExpression struct {
	literal    string
	expression common.BoolExpression
}

func (what *NotExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	item, errorScript, itemError := new(ExpressionList).ParseAny(script)
	if itemError != nil {
		return nil, errorScript, fmt.Errorf("failed to parse not-expression: %w", itemError)
	}

	switch castItem := item.(type) {
	case common.BoolExpression:
		what.expression = castItem

	default:
		return nil, script, fmt.Errorf("not-expression requires a bool expression, got %T", castItem)
	}

	return what, nil, nil
}

func (what *NotExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *NotExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	value, errorLiteral, evalError := what.expression.EvalBool(scope)
	if evalError != nil {
		return common.EmptyBoolValue(), errorLiteral, fmt.Errorf("%q: error evaluating not-expression: %w", what.literal, evalError)
	}

	return common.SomeBoolValue(!value.BoolValue(), value.Event()), "", nil
}

func (what *NotExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *NotExpression) Literal() string {
	return what.literal
}
