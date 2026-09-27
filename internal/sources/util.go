package sources

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/term"
)

const (
	// OptimizationFillFactor mirrors asnlookup-utils' default optimization level 5.
	OptimizationFillFactor = float32(9-5) * 0.125
)

// isTerminal reports whether f is an interactive terminal. A character device
// is not enough: /dev/null is one, and stdin redirected from it under cron must
// not be taken for someone to ask.
func isTerminal(f *os.File) bool {
	return f != nil && term.IsTerminal(int(f.Fd()))
}

// WriteFileAtomic writes data to a temp file in the destination directory and renames it into place.
func WriteFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// StreamFileAtomic is WriteFileAtomic for payloads too large to hold in memory.
func StreamFileAtomic(path string, r io.Reader) (int64, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	n, err := io.Copy(tmp, r)
	if err != nil {
		tmp.Close()
		return n, err
	}
	if err := tmp.Close(); err != nil {
		return n, err
	}
	return n, os.Rename(tmpName, path)
}
