package expressions

import (
	"fmt"
	"regexp"

	"github.com/threagile/threagile/pkg/risks/script/common"
)

// RegexMatchExpression tests whether a string value matches a regular expression pattern.
//
//	regex-match:
//	  pattern: "^admin"
//	  value: "{tech_asset.title}"
type RegexMatchExpression struct {
	literal string
	pattern common.StringExpression
	value   common.StringExpression
}

func (what *RegexMatchExpression) ParseBool(script any) (common.BoolExpression, any, error) {
	what.literal = common.ToLiteral(script)

	castScript, ok := script.(map[string]any)
	if !ok {
		return nil, script, fmt.Errorf("failed to parse regex-match-expression: expected map, got %T", script)
	}

	for key, val := range castScript {
		switch key {
		case "pattern":
			expr, errScript, itemErr := new(ValueExpression).ParseString(val)
			if itemErr != nil {
				return nil, errScript, fmt.Errorf("failed to parse %q of regex-match-expression: %w", key, itemErr)
			}
			what.pattern = expr

		case "value":
			expr, errScript, itemErr := new(ValueExpression).ParseString(val)
			if itemErr != nil {
				return nil, errScript, fmt.Errorf("failed to parse %q of regex-match-expression: %w", key, itemErr)
			}
			what.value = expr

		default:
			return nil, script, fmt.Errorf("failed to parse regex-match-expression: unexpected key %q", key)
		}
	}

	if what.pattern == nil {
		return nil, script, fmt.Errorf("regex-match-expression requires a 'pattern' field")
	}
	if what.value == nil {
		return nil, script, fmt.Errorf("regex-match-expression requires a 'value' field")
	}

	return what, nil, nil
}

func (what *RegexMatchExpression) ParseAny(script any) (common.Expression, any, error) {
	return what.ParseBool(script)
}

func (what *RegexMatchExpression) EvalBool(scope *common.Scope) (*common.BoolValue, string, error) {
	patternValue, errLiteral, patternErr := what.pattern.EvalString(scope)
	if patternErr != nil {
		return common.EmptyBoolValue(), errLiteral, fmt.Errorf("regex-match-expression: failed to eval pattern: %w", patternErr)
	}

	valueValue, errLiteral, valueErr := what.value.EvalString(scope)
	if valueErr != nil {
		return common.EmptyBoolValue(), errLiteral, fmt.Errorf("regex-match-expression: failed to eval value: %w", valueErr)
	}

	re, compileErr := regexp.Compile(patternValue.StringValue())
	if compileErr != nil {
		return common.EmptyBoolValue(), what.literal, fmt.Errorf("regex-match-expression: invalid pattern %q: %w", patternValue.StringValue(), compileErr)
	}

	matched := re.MatchString(valueValue.StringValue())
	return common.SomeBoolValue(matched, valueValue.Event()), "", nil
}

func (what *RegexMatchExpression) EvalAny(scope *common.Scope) (common.Value, string, error) {
	return what.EvalBool(scope)
}

func (what *RegexMatchExpression) Literal() string {
	return what.literal
}
