package bundle

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// dirReader reads an extracted bundle directory through the operating
// system, exactly as verify.php does when given a directory.
type dirReader struct {
	dir string
}

func (d *dirReader) path(name string) string {
	return filepath.Join(d.dir, filepath.FromSlash(name))
}

func (d *dirReader) IsFile(name string) bool {
	info, err := os.Stat(d.path(name))
	return err == nil && info.Mode().IsRegular()
}

func (d *dirReader) Open(name string) (io.ReadCloser, error) {
	f, err := os.Open(d.path(name))
	if err != nil {
		return nil, &HardError{Message: fmt.Sprintf("could not read [%s]", d.path(name)), Code: 1}
	}
	return f, nil
}

func (d *dirReader) ReadWhole(name string) ([]byte, error) {
	if !d.IsFile(name) {
		return nil, nil
	}
	return readCapped(d.path(name), func() (io.ReadCloser, error) { return os.Open(d.path(name)) })
}

func (d *dirReader) Close() error { return nil }

// readCapped reads a whole file, refusing anything over MaxWholeFileBytes.
func readCapped(label string, open func() (io.ReadCloser, error)) ([]byte, error) {
	f, err := open()
	if err != nil {
		return nil, &HardError{Message: fmt.Sprintf("could not read [%s]", label), Code: 1}
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxWholeFileBytes+1))
	if err != nil {
		return nil, &HardError{Message: fmt.Sprintf("could not read [%s]", label), Code: 1}
	}
	if len(data) > MaxWholeFileBytes {
		return nil, &HardError{
			Message: fmt.Sprintf("[%s] is larger than the %d bytes this verifier reads into memory; nothing was verified", label, MaxWholeFileBytes),
			Code:    2,
		}
	}
	return data, nil
}
