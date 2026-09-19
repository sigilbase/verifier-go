package verify

import (
	"time"

	"github.com/sigilbase/verifier-go/internal/bundle"
	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/internal/phpcompat"
)

// run is the state one invocation accumulates: verify.php's globals.
type run struct {
	opts *Options

	trusted          *KeySet
	trustedSetSource string
	tsaRoots         string
	tsaRootsSource   string

	results  *Results
	failures []string
	notes    []string
	log      []LogLine
	keys     keySources
}

func newRun(opts *Options) *run {
	r := &run{opts: opts, results: newResults()}
	r.trusted = opts.Keys
	r.trustedSetSource = opts.KeysSource
	if r.trusted == nil {
		r.trusted = EmbeddedKeys()
		r.trustedSetSource = "built-in trusted set"
	}
	if opts.TSARoots != nil {
		r.tsaRoots = *opts.TSARoots
		r.tsaRootsSource = opts.TSARootsSource
	} else {
		r.tsaRoots = EmbeddedTSARoots()
		r.tsaRootsSource = "built-in trusted set"
	}
	return r
}

// report records a failed check against a result (verify.php's report).
// Content integrity is the default, as the largest category and the safe
// direction for a caller that forgets to say.
func (r *run) report(message string, result string) {
	if result == "" {
		result = ResultContent
	}
	r.failures = append(r.failures, message)
	r.results.demote(result, StateFail)
	r.log = append(r.log, LogLine{Kind: "fail", Text: message})
}

// unconfirmed records a check that could not be completed, as distinct
// from one that failed.
func (r *run) unconfirmed(message string, result string) {
	r.notes = append(r.notes, message)
	r.results.demote(result, StateUnconfirmed)
	r.log = append(r.log, LogLine{Kind: "unconfirmed", Text: message})
}

func (r *run) note(message string) {
	r.notes = append(r.notes, message)
	r.log = append(r.log, LogLine{Kind: "note", Text: message})
}

func (r *run) info(message string) {
	r.log = append(r.log, LogLine{Kind: "info", Text: message})
}

// hardError is verify.php's fail_hard: verification stops without a
// verdict. Code 1 when the bundle cannot pass, 2 when nothing was verified.
type hardError = bundle.HardError

func hard(message string, code int) *hardError {
	return &hardError{Message: message, Code: code}
}

// parseRFC3339 reads a bundle timestamp the way verify.php's parse_rfc3339
// does from 1.6.0: a value that PHP's date parser would refuse counts as
// unparseable rather than aborting the run.
func parseRFC3339(s string) (time.Time, bool) {
	return phpcompat.ParseRFC3339(s)
}

// parseRFC3339Value applies parseRFC3339 to a decoded value, which must be
// a string.
func parseRFC3339Value(v *cjson.Value) (time.Time, bool) {
	if !isString(v) {
		return time.Time{}, false
	}
	return parseRFC3339(v.Str)
}
