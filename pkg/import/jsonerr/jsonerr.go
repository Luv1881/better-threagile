// Package jsonerr annotates encoding/json parse errors with the line and
// column of the failure, so importer error messages point users at the
// offending spot in their file instead of just echoing Go's byte-offset-free
// message.
package jsonerr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// WithPosition returns err's message suffixed with "(line N, column M)" when
// err is a *json.SyntaxError or *json.UnmarshalTypeError carrying a byte
// offset into data. Any other error is returned unchanged.
func WithPosition(data []byte, err error) error {
	var offset int64

	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntaxErr):
		offset = syntaxErr.Offset
	case errors.As(err, &typeErr):
		offset = typeErr.Offset
	default:
		return err
	}

	if offset <= 0 || offset > int64(len(data)) {
		return err
	}

	prefix := data[:offset]
	line := bytes.Count(prefix, []byte("\n")) + 1
	column := offset - int64(bytes.LastIndexByte(prefix, '\n'))

	return fmt.Errorf("%w (line %d, column %d)", err, line, column)
}
