package verify

import (
	"bytes"
	"encoding/json"
)

// The five results and their four states, as verify.php reports them.
const (
	ResultContent    = "content_integrity"
	ResultIdentity   = "signing_identity"
	ResultTimestamps = "timestamps"
	ResultScope      = "scope"
	ResultRedactions = "redactions"

	StatePass        = "pass"
	StateNotChecked  = "not_checked"
	StateUnconfirmed = "unconfirmed"
	StateFail        = "fail"
)

// resultOrder is the order the results are reported in.
var resultOrder = []string{ResultContent, ResultIdentity, ResultTimestamps, ResultScope, ResultRedactions}

// Exit codes.
const (
	ExitPass        = 0
	ExitFail        = 1
	ExitError       = 2
	ExitUnconfirmed = 3
)

// Results holds one state per result, in report order.
type Results struct {
	states map[string]string
}

func newResults() *Results {
	r := &Results{states: map[string]string{}}
	for _, k := range resultOrder {
		r.states[k] = StatePass
	}
	return r
}

// Get returns the state of a result.
func (r *Results) Get(name string) string { return r.states[name] }

// demote lowers a result. Nothing ever raises one, so the order of checks
// cannot change the verdict (verify.php's demote).
func (r *Results) demote(name, state string) {
	rank := map[string]int{StatePass: 0, StateNotChecked: 1, StateUnconfirmed: 2, StateFail: 3}
	if rank[state] > rank[r.states[name]] {
		r.states[name] = state
	}
}

// MarshalJSON writes the results as an object in report order.
func (r *Results) MarshalJSON() ([]byte, error) {
	return marshalOrdered(resultOrder, func(k string) any { return r.states[k] })
}

// exitCode is verify.php's verdict_code: any failure is a failure;
// otherwise anything unconfirmed is unconfirmed; otherwise a pass.
func (r *Results) exitCode() int {
	for _, k := range resultOrder {
		if r.states[k] == StateFail {
			return ExitFail
		}
	}
	for _, k := range resultOrder {
		if r.states[k] == StateUnconfirmed {
			return ExitUnconfirmed
		}
	}
	return ExitPass
}

// VerdictWord is the first word of the human report for an exit code.
func VerdictWord(code int) string {
	switch code {
	case ExitPass:
		return "PASS"
	case ExitFail:
		return "FAIL"
	case ExitUnconfirmed:
		return "UNCONFIRMED"
	}
	return "ERROR"
}

// KeySource records where trust in a signing key came from.
type KeySource struct {
	Fingerprint string
	Source      string
}

// TreeState is a cumulative RFC 6962 tree state: size and root.
type TreeState struct {
	TreeSize int64  `json:"tree_size"`
	Root     string `json:"root"`
}

// Range is a manifest range.
type Range struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// BundleInfo describes one verified bundle in the JSON document.
type BundleInfo struct {
	Path           string
	Stream         string
	Range          Range
	Events         int64
	Checkpoints    int64
	RedactedEvents int64
	// full says whether the events, checkpoints and redacted_events
	// fields are written (they are in verify mode only).
	full bool
}

// ConsistencyInfo is the proof summary of the two-bundle mode.
type ConsistencyInfo struct {
	Old        TreeState `json:"old"`
	New        TreeState `json:"new"`
	ProofNodes int       `json:"proof_nodes"`
}

// PathHash is the SHA-256 of a bundle file argument; nil for a directory
// or a path that does not exist.
type PathHash struct {
	Path string
	Hash *string
}

// LogLine is one line of the human-readable account, in the order the
// checks produced it.
type LogLine struct {
	Kind string // "fail", "unconfirmed", "note", "info"
	Text string
}

// Report is the outcome of a run. It marshals to the document described by
// result.schema.json, byte-compatible in content with verify.php's --json
// output apart from the implementation identity fields and the free text
// of failures and notes.
type Report struct {
	VerifierName    string
	VerifierVersion string
	VerifierSHA256  string

	// Result is pass, fail, unconfirmed or error. ExitCode is the process
	// exit code the result maps to.
	Result   string
	ExitCode int

	// Hard is set when verification stopped before a verdict (verify.php's
	// fail_hard); Message then says why and the fields below are empty.
	Hard    bool
	Message string

	Results     *Results
	SigningKeys []KeySource
	Mode        string

	Bundle           *BundleInfo
	ConsistencyState *TreeState
	Bundles          []BundleInfo
	Consistency      *ConsistencyInfo
	Recorded         *TreeState

	Failures []string
	Notes    []string

	// BundleSHA256 is present only when Options.PrintHashes was set.
	PrintHashes  bool
	BundleSHA256 []PathHash

	// Log is the chronological account for the human report; it is not
	// part of the JSON document.
	Log []LogLine
}

// MarshalJSON writes the document with the same field order as
// verify.php, so that a diff between the two is a diff of values.
func (r *Report) MarshalJSON() ([]byte, error) {
	var keys []string
	values := map[string]any{}
	add := func(k string, v any) {
		keys = append(keys, k)
		values[k] = v
	}
	add("verifier_name", r.VerifierName)
	add("verifier_version", r.VerifierVersion)
	if r.Hard {
		add("result", "error")
		add("exit_code", r.ExitCode)
		add("message", r.Message)
		return marshalOrdered(keys, func(k string) any { return values[k] })
	}
	add("verifier_sha256", r.VerifierSHA256)
	add("result", r.Result)
	add("exit_code", r.ExitCode)
	add("results", r.Results)
	add("signing_keys", keySourcesJSON(r.SigningKeys))
	add("mode", r.Mode)
	switch r.Mode {
	case "verify":
		add("bundle", r.Bundle)
		add("consistency_state", r.ConsistencyState)
	case "consistency-bundles":
		add("bundles", r.Bundles)
		add("consistency", r.Consistency)
	case "consistency-recorded-root":
		add("bundle", r.Bundle)
		add("recorded", r.Recorded)
	}
	add("failures", nonNil(r.Failures))
	add("notes", nonNil(r.Notes))
	if r.PrintHashes {
		add("bundle_sha256", pathHashesJSON(r.BundleSHA256))
	}
	return marshalOrdered(keys, func(k string) any { return values[k] })
}

// MarshalJSON writes a bundle description; the counts appear only in
// verify mode, as in verify.php.
func (b *BundleInfo) MarshalJSON() ([]byte, error) {
	keys := []string{"path", "stream", "range"}
	values := map[string]any{"path": b.Path, "stream": b.Stream, "range": b.Range}
	if b.full {
		keys = append(keys, "events", "checkpoints", "redacted_events")
		values["events"] = b.Events
		values["checkpoints"] = b.Checkpoints
		values["redacted_events"] = b.RedactedEvents
	}
	return marshalOrdered(keys, func(k string) any { return values[k] })
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// keySourcesJSON reproduces PHP's json_encode of the $keySources array:
// an object keyed by fingerprint, or an empty JSON array when there are
// no keys at all (an empty PHP array encodes as []).
type orderedObject struct {
	keys   []string
	values map[string]any
}

func (o orderedObject) MarshalJSON() ([]byte, error) {
	if len(o.keys) == 0 {
		return []byte("[]"), nil
	}
	return marshalOrdered(o.keys, func(k string) any { return o.values[k] })
}

func keySourcesJSON(sources []KeySource) orderedObject {
	o := orderedObject{values: map[string]any{}}
	for _, s := range sources {
		o.keys = append(o.keys, s.Fingerprint)
		o.values[s.Fingerprint] = s.Source
	}
	return o
}

func pathHashesJSON(hashes []PathHash) orderedObject {
	o := orderedObject{values: map[string]any{}}
	for _, h := range hashes {
		if _, seen := o.values[h.Path]; !seen {
			o.keys = append(o.keys, h.Path)
		}
		if h.Hash == nil {
			o.values[h.Path] = nil
		} else {
			o.values[h.Path] = *h.Hash
		}
	}
	return o
}

// marshalOrdered encodes an object with its keys in the given order,
// without HTML escaping, so the document reads as verify.php's does.
func marshalOrdered(keys []string, value func(string) any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := encodeJSON(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := encodeJSON(value(k))
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// JSON renders the report as an indented document, four spaces per level
// as PHP's JSON_PRETTY_PRINT uses.
func (r *Report) JSON() ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "    "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
