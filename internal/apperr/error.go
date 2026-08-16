package apperr

import "fmt"

const (
	Operational  = 1
	Usage        = 2
	Verification = 3
	Renewal      = 4
	Revoked      = 5
)

type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

func Make(code int, message string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(message, args...)}
}

func Code(err error) int {
	if e, ok := err.(*Error); ok {
		return e.Code
	}

	return Operational
}
