package utils

import "errors"

var PgDuplicateKeyMsg = "duplicate key value violates unique constraint"

type CustomErrorWrapper struct {
	Message string `json:"message"` // Human-readable message for clients
	Code    int    `json:"-"`       // HTTP Status code. We use `-` to skip json marshaling.
	Err     error  `json:"-"`       // The original error. Same reason as above.
}

func NewErrorWrapper(code int, err error, message string) error {
	return CustomErrorWrapper{
		Message: message,
		Code:    code,
		Err:     err,
	}
}

// Returns Message if Err is nil. You can handle custom implementation of your own.
func (err CustomErrorWrapper) Error() string {
	// guard against panics
	if err.Err != nil {
		return err.Err.Error()
	}
	return err.Message
}

func (err CustomErrorWrapper) Unwrap() error {
	return err.Err // Returns inner error
}

// Dig Returns the innermost CustomErrorWrapper
func (err CustomErrorWrapper) Dig() CustomErrorWrapper {
	var ew CustomErrorWrapper
	if errors.As(err.Err, &ew) {
		// Recursively digs until wrapper error is not in which case it will stop
		return ew.Dig()
	}
	return err
}
