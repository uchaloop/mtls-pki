//go:build !windows

package storage

import (
	"errors"
	"os"
	"syscall"
)

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}

	syncErr := directory.Sync()
	closeErr := directory.Close()

	if syncErr != nil && !errors.Is(syncErr, syscall.EINVAL) {
		return syncErr
	}

	return closeErr
}
