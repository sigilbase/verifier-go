// Package verify is the Sigilbase evidence bundle verifier as a library:
// the same checks as verify.php, in Go, conforming to FORMAT.md, the
// golden vectors and the conformance corpus. The command in
// cmd/sigilbase-verify is a thin front for it, and other Sigilbase Go
// programs import it rather than reimplementing hashing or proofs.
//
// Every check here mirrors a function in verify.php by name in the
// comments, because the two implementations are held to agree fixture by
// fixture, and a reader chasing a difference needs to find the other side
// quickly.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

// Name and Version identify this implementation in reports. Version is
// set from the release tag through -ldflags at build time.
var (
	Name    = "sigilbase-verify"
	Version = "dev"
)

// Options configure a run.
type Options struct {
	// Keys replaces the built-in trusted signing key set wholesale; nil
	// means the embedded set. KeysSource is how the report names it
	// (verify.php prints "--keys <file>").
	Keys       *KeySet
	KeysSource string

	// TSARoots replaces the built-in timestamp trust roots (PEM text);
	// nil means the embedded roots. TSARootsSource names it likewise.
	TSARoots       *string
	TSARootsSource string

	// SkipAnchors skips RFC 3161 anchor validation.
	SkipAnchors bool

	// PrintHashes adds the SHA-256 of each bundle file argument to the
	// report.
	PrintHashes bool
}

// Bundle verifies one bundle, given as a zip archive or an extracted
// directory. It never returns an error for anything the bundle says: a
// bundle that cannot be verified yields a Report with Hard set.
func Bundle(path string, opts Options) *Report {
	r := newRun(&opts)
	rep := r.newReport()
	rep.Mode = "verify"
	rep.BundleSHA256 = []PathHash{pathHash(path)}

	result, herr := r.verifyBundle(path, opts.SkipAnchors, nil, nil)
	if herr != nil {
		return r.finishHard(rep, herr)
	}

	code := r.results.exitCode()
	var state *TreeState
	if code != ExitFail {
		if root, ok := result.cumulativeRoots[result.rangeTo]; result.rangeFrom == 1 && ok {
			state = &TreeState{TreeSize: result.rangeTo, Root: root}
		}
	}
	rep.Bundle = &BundleInfo{
		Path:           path,
		Stream:         result.streamID,
		Range:          Range{From: result.rangeFrom, To: result.rangeTo},
		Events:         result.eventCount,
		Checkpoints:    result.checkpointCount,
		RedactedEvents: result.redactedCount,
		full:           true,
	}
	rep.ConsistencyState = state
	return r.finish(rep, code)
}

func (r *run) newReport() *Report {
	return &Report{
		VerifierName:    Name,
		VerifierVersion: Version,
		VerifierSHA256:  SelfSHA256(),
		PrintHashes:     r.opts.PrintHashes,
	}
}

func (r *run) finish(rep *Report, code int) *Report {
	rep.Result = lower(VerdictWord(code))
	rep.ExitCode = code
	rep.Results = r.results
	rep.SigningKeys = r.keys.list()
	rep.Failures = nonNil(r.failures)
	rep.Notes = nonNil(r.notes)
	rep.Log = r.log
	return rep
}

func (r *run) finishHard(rep *Report, herr *hardError) *Report {
	rep.Hard = true
	rep.Result = "error"
	rep.ExitCode = herr.Code
	rep.Message = herr.Message
	rep.Results = r.results
	rep.SigningKeys = r.keys.list()
	rep.Failures = nonNil(r.failures)
	rep.Notes = nonNil(r.notes)
	rep.Log = append(r.log, LogLine{Kind: "hard", Text: herr.Message})
	return rep
}

// pathHash is the SHA-256 of a bundle file argument, or nil for a
// directory or a path that cannot be read (verify.php hashes each file
// argument before verifying).
func pathHash(path string) PathHash {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return PathHash{Path: path}
	}
	f, err := os.Open(path)
	if err != nil {
		return PathHash{Path: path}
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return PathHash{Path: path}
	}
	s := hex.EncodeToString(h.Sum(nil))
	return PathHash{Path: path, Hash: &s}
}

var (
	selfOnce sync.Once
	selfHash string
)

// SelfSHA256 is the SHA-256 of the running binary, which is what a report
// records as the identity of the verifier that ran (verify.php records the
// hash of its own file). It is "unavailable" when the executable cannot be
// read back.
func SelfSHA256() string {
	selfOnce.Do(func() {
		selfHash = "unavailable"
		exe, err := os.Executable()
		if err != nil {
			return
		}
		f, err := os.Open(exe)
		if err != nil {
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return
		}
		selfHash = hex.EncodeToString(h.Sum(nil))
	})
	return selfHash
}
