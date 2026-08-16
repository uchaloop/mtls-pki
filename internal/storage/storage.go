package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gofrs/flock"
)

type Lock struct{ file *flock.Flock }

func Acquire(ctx context.Context, pkiDir string, shared bool) (*Lock, error) {
	if err := os.MkdirAll(pkiDir, 0700); err != nil {
		return nil, err
	}

	f := flock.New(filepath.Join(pkiDir, ".pki.lock"))

	var ok bool
	var err error

	if shared {
		ok, err = f.TryRLockContext(ctx, 100*time.Millisecond)
	} else {
		ok, err = f.TryLockContext(ctx, 100*time.Millisecond)
	}

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, errors.New("could not acquire PKI lock")
	}

	return &Lock{file: f}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}

	return l.file.Unlock()
}

func WriteAtomic(path string, data []byte, mode os.FileMode, replace bool) error {
	if !replace {
		if _, e := os.Stat(path); e == nil {
			return fmt.Errorf("%s exists", path)
		} else if !os.IsNotExist(e) {
			return e
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	f, e := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if e != nil {
		return e
	}

	tmp := f.Name()
	defer os.Remove(tmp)

	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(data)
	}

	if e == nil {
		e = f.Sync()
	}

	closeErr := f.Close()
	if e != nil {
		return e
	}

	if closeErr != nil {
		return closeErr
	}

	if e = os.Rename(tmp, path); e != nil {
		return e
	}

	// The directory is synced separately, otherwise the rename may not survive a power loss.
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}

	syncErr := dir.Sync()
	closeErr = dir.Close()

	if syncErr != nil && !errors.Is(syncErr, syscall.EINVAL) {
		return syncErr
	}

	return closeErr
}
