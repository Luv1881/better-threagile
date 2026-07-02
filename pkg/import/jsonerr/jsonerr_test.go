package jsonerr

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestWithPositionSyntaxError(t *testing.T) {
	data := []byte("{\n  \"name\": \"ok\",\n  \"bad\": tru}\n")
	var v map[string]any
	err := json.Unmarshal(data, &v)
	if err == nil {
		t.Fatal("expected a syntax error")
	}

	annotated := WithPosition(data, err)
	if !strings.Contains(annotated.Error(), "line 3") {
		t.Errorf("expected line 3 in error, got: %v", annotated)
	}
	if !errors.Is(annotated, err) {
		t.Error("annotated error must wrap the original")
	}
}

func TestWithPositionTypeError(t *testing.T) {
	data := []byte("{\n  \"count\": \"not-a-number\"\n}\n")
	var v struct {
		Count int `json:"count"`
	}
	err := json.Unmarshal(data, &v)
	if err == nil {
		t.Fatal("expected a type error")
	}

	annotated := WithPosition(data, err)
	if !strings.Contains(annotated.Error(), "line 2") {
		t.Errorf("expected line 2 in error, got: %v", annotated)
	}
}

func TestWithPositionPassthrough(t *testing.T) {
	plain := errors.New("something else")
	if got := WithPosition([]byte("{}"), plain); got != plain {
		t.Errorf("non-JSON errors must pass through unchanged, got: %v", got)
	}
}
