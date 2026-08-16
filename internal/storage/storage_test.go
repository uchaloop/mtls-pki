package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExclusiveLockAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(context.Background(), dir, false)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err = Acquire(ctx, dir, false); err == nil {
		t.Fatal("second exclusive lock succeeded")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "state", "value")
	if err = WriteAtomic(path, []byte("one"), 0600, false); err != nil {
		t.Fatal(err)
	}
	if err = WriteAtomic(path, []byte("two"), 0600, false); err == nil {
		t.Fatal("unexpected overwrite")
	}
	if err = WriteAtomic(path, []byte("two"), 0600, true); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil || string(b) != "two" {
		t.Fatalf("content=%q err=%v", b, err)
	}
}
