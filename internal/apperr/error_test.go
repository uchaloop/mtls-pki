package apperr

import (
	"errors"
	"fmt"
	"testing"
)

func TestCodeAndUnwrap(t *testing.T) {
	inner := errors.New("boom")
	err := &Error{Code: Verification, Err: inner}
	if Code(err) != Verification {
		t.Fatal("wrong code")
	}
	if !errors.Is(err, inner) {
		t.Fatal("unwrap failed")
	}

	wrapped := fmt.Errorf("context: %w", err)
	if Code(wrapped) != Operational {
		t.Fatal("Code intentionally accepts only direct errors")
	}
	if Code(errors.New("plain")) != Operational {
		t.Fatal("plain error must be operational")
	}
}

func TestNew(t *testing.T) {
	err := Make(Usage, "bad %s", "flag")
	if err.Error() != "bad flag" || Code(err) != Usage {
		t.Fatalf("unexpected error: %v", err)
	}
}
