package secretinput

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadSources(t *testing.T) {
	t.Setenv("TEST_SECRET", "env-value")
	value, err := (Source{Env: "TEST_SECRET"}).Read(bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil || string(value) != "env-value" {
		t.Fatalf("env: %q %v", value, err)
	}

	path := filepath.Join(t.TempDir(), "secret")
	if err = os.WriteFile(path, []byte("file-value\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	value, err = (Source{File: path}).Read(bytes.NewBuffer(nil), bytes.NewBuffer(nil))
	if err != nil || string(value) != "file-value" {
		t.Fatalf("file: %q %v", value, err)
	}

	value, err = (Source{Stdin: true}).Read(bytes.NewBufferString("stdin-value\n"), bytes.NewBuffer(nil))
	if err != nil || string(value) != "stdin-value" {
		t.Fatalf("stdin: %q %v", value, err)
	}
}

func TestReadRejectsConflictsAndMissingEnv(t *testing.T) {
	if _, err := (Source{Env: "A", Stdin: true}).Read(bytes.NewBuffer(nil), bytes.NewBuffer(nil)); err == nil {
		t.Fatal("conflicting sources accepted")
	}

	os.Unsetenv("DEFINITELY_MISSING_SECRET")
	if _, err := (Source{Env: "DEFINITELY_MISSING_SECRET"}).Read(bytes.NewBuffer(nil), bytes.NewBuffer(nil)); err == nil {
		t.Fatal("missing env accepted")
	}
}

func TestClear(t *testing.T) {
	value := []byte("secret")
	Clear(value)
	for _, b := range value {
		if b != 0 {
			t.Fatal("secret was not cleared")
		}
	}
}
