package common

import (
	"fmt"
	"strings"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/types"
)

const (
	calculateSeverity = "calculate_severity"
	builtinLower      = "lower"
	builtinUpper      = "upper"
	builtinTrim       = "trim"
	builtinLen        = "len"
)

var (
	callers = map[string]builtInFunc{
		calculateSeverity: calculateSeverityFunc,
		builtinLower:      lowerFunc,
		builtinUpper:      upperFunc,
		builtinTrim:       trimFunc,
		builtinLen:        lenFunc,
	}
)

type builtInFunc func(parameters []Value) (Value, error)

func IsBuiltIn(builtInName string) bool {
	_, ok := callers[builtInName]
	return ok
}

func CallBuiltIn(builtInName string, parameters ...Value) (Value, error) {
	caller, ok := callers[builtInName]
	if !ok {
		return nil, fmt.Errorf("unknown built-in %v", builtInName)
	}

	return caller(parameters)
}

func calculateSeverityFunc(parameters []Value) (Value, error) {
	if len(parameters) != 2 {
		return nil, fmt.Errorf("failed to calculate severity: expected 2 parameters, got %d", len(parameters))
	}

	likelihoodValue, likelihoodError := toLikelihood(parameters[0])
	if likelihoodError != nil {
		return nil, fmt.Errorf("failed to calculate severity: %w", likelihoodError)
	}
	likelihoodDecimalValue, ok := likelihoodValue.Value().(decimal.Decimal)
	if !ok {
		return nil, fmt.Errorf("failed to calculate severity: likelihood is not a decimal, got %T", likelihoodValue.Value())
	}
	likelihoodDecimal := likelihoodDecimalValue.IntPart()

	impactValue, impactError := toImpact(parameters[1])
	if impactError != nil {
		return nil, fmt.Errorf("failed to calculate severity: %w", impactError)
	}
	impactDecimalValue, ok := impactValue.Value().(decimal.Decimal)
	if !ok {
		return nil, fmt.Errorf("failed to calculate severity: impact is not a decimal, got %T", impactValue.Value())
	}
	impactDecimal := impactDecimalValue.IntPart()

	return SomeStringValue(types.CalculateSeverity(types.RiskExploitationLikelihood(likelihoodDecimal), types.RiskExploitationImpact(impactDecimal)).String(), nil), nil
}

func requireOneString(name string, parameters []Value) (string, error) {
	if len(parameters) != 1 {
		return "", fmt.Errorf("%s: expected 1 parameter, got %d", name, len(parameters))
	}
	s, ok := parameters[0].Value().(string)
	if !ok {
		return "", fmt.Errorf("%s: parameter must be a string, got %T", name, parameters[0].Value())
	}
	return s, nil
}

func lowerFunc(parameters []Value) (Value, error) {
	s, err := requireOneString("lower", parameters)
	if err != nil {
		return nil, err
	}
	return SomeStringValue(strings.ToLower(s), nil), nil
}

func upperFunc(parameters []Value) (Value, error) {
	s, err := requireOneString("upper", parameters)
	if err != nil {
		return nil, err
	}
	return SomeStringValue(strings.ToUpper(s), nil), nil
}

func trimFunc(parameters []Value) (Value, error) {
	s, err := requireOneString("trim", parameters)
	if err != nil {
		return nil, err
	}
	return SomeStringValue(strings.TrimSpace(s), nil), nil
}

func lenFunc(parameters []Value) (Value, error) {
	if len(parameters) != 1 {
		return nil, fmt.Errorf("len: expected 1 parameter, got %d", len(parameters))
	}
	switch v := parameters[0].Value().(type) {
	case string:
		return SomeDecimalValue(decimal.NewFromInt(int64(len(v))), nil), nil
	case []any:
		return SomeDecimalValue(decimal.NewFromInt(int64(len(v))), nil), nil
	case []Value:
		return SomeDecimalValue(decimal.NewFromInt(int64(len(v))), nil), nil
	default:
		return nil, fmt.Errorf("len: unsupported type %T", parameters[0].Value())
	}
}
