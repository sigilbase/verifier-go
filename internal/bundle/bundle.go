// Package bundle opens an evidence bundle, given as a zip archive or an
// extracted directory, and hands its files to the verifier one at a time.
//
// verify.php extracts a zip to a temporary directory with ZipArchive and
// then reads ordinary files. What it ends up reading therefore depends on
// how PHP's extraction treats entry names: paths are normalised, a later
// entry overwrites an earlier one of the same normalised name, and a name
// that collides with a directory aborts the extraction. This package
// reproduces those rules without touching the disk, so that both verifiers
// read the same bytes for the same archive. The rules are those of PHP on
// Linux, the platform the differential job runs on; FORMAT.md records them.
package bundle

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Limits the Go verifier enforces where verify.php relies on PHP's memory
// limit. Both are generous: a single event line is normally well under a
// megabyte, and the files read whole (manifest, checkpoints, anchors,
// consistency, redactions, declaration proofs, SigilSign blocks) are a few
// megabytes at most in any real export. Exceeding a limit is reported as an
// error (exit 2): nothing was verified.
const (
	// MaxLineBytes is the longest line events.ndjson or declarations.ndjson
	// may carry.
	MaxLineBytes = 64 << 20
	// MaxWholeFileBytes is the largest bundle file the verifier will read
	// into memory in one piece.
	MaxWholeFileBytes = 512 << 20
	// MaxEntryBytes is the largest decompressed size of any single zip
	// entry, streamed or not.
	MaxEntryBytes = 64 << 30
)

// HardError is a failure that stops verification before a verdict, exactly
// as verify.php's fail_hard does: Code 1 when the bundle cannot pass
// (missing or unreadable pieces are indistinguishable from deletion) and
// Code 2 when nothing was verified at all.
type HardError struct {
	Message string
	Code    int
}

func (e *HardError) Error() string { return e.Message }

// Reader is an opened bundle.
type Reader interface {
	// IsFile reports whether name exists as a regular file, as PHP's
	// is_file would for the extracted bundle.
	IsFile(name string) bool
	// Open streams a file. The returned error is a *HardError when the
	// file cannot be read.
	Open(name string) (io.ReadCloser, error)
	// ReadWhole reads a file into memory, subject to MaxWholeFileBytes. A
	// missing file reads as empty, matching (string) file_get_contents().
	ReadWhole(name string) ([]byte, error)
	// Close releases the archive.
	Close() error
}

// Open locates a bundle the way verify.php's locate_bundle does: a
// directory is used as it stands, a file must be a zip archive, and
// anything else does not exist.
func Open(path string) (Reader, *HardError) {
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		return &dirReader{dir: strings.TrimRight(path, `/\`)}, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, &HardError{Message: fmt.Sprintf("bundle [%s] does not exist", path), Code: 2}
	}
	r, herr := openZip(path)
	if herr != nil {
		return nil, herr
	}
	return r, nil
}

// ErrLineTooLong is returned by Lines when a line exceeds MaxLineBytes.
var ErrLineTooLong = errors.New("line exceeds the maximum length this verifier accepts")

// IsBlank reports whether PHP's trim($line) === ” holds for a line that
// has already lost its trailing CR and LF: every byte is one of the six
// characters trim strips by default.
func IsBlank(line []byte) bool {
	for _, b := range line {
		switch b {
		case ' ', '\t', '\n', '\r', 0, '\v':
		default:
			return false
		}
	}
	return true
}
