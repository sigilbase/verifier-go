// Package difftest runs verify.php and sigilbase-verify on the same input
// and compares what they say. The differential job in CI, the corpus
// tests and the mutation runner all use it, so that "the two verifiers
// agree" means one thing everywhere.
package difftest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
)

// Runner knows how to invoke both verifiers.
type Runner struct {
	// PHP is the php binary and PHPArgs any leading arguments (an ini
	// file, say); VerifyPHP is the path to verify.php.
	PHP       string
	PHPArgs   []string
	VerifyPHP string
	// GoBinary is the built sigilbase-verify.
	GoBinary string
	// Dir is the working directory for both, so relative fixture paths
	// and the bundle.path field agree.
	Dir string
}

// Outcome is one verifier's answer.
type Outcome struct {
	Exit   int
	Doc    map[string]any // the --json document, or nil when stdout held none
	Stdout string
	Stderr string
}

// RunPHP runs verify.php with --json and the given arguments.
func (r *Runner) RunPHP(args ...string) (*Outcome, error) {
	full := append(append([]string{}, r.PHPArgs...), r.VerifyPHP, "--json")
	full = append(full, args...)
	return r.exec(r.PHP, full)
}

// RunGo runs sigilbase-verify with --json and the given arguments.
func (r *Runner) RunGo(args ...string) (*Outcome, error) {
	return r.exec(r.GoBinary, append([]string{"--json"}, args...))
}

func (r *Runner) exec(bin string, args []string) (*Outcome, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = r.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			return nil, fmt.Errorf("%s: %w", bin, err)
		}
		code = ee.ExitCode()
	}
	out := &Outcome{Exit: code, Stdout: stdout.String(), Stderr: stderr.String()}
	out.Doc = parseDoc(out.Stdout)
	return out, nil
}

// parseDoc finds the JSON document in stdout. PHP configurations that
// print warnings to stdout put them before the document; the document
// starts at the first "{" on a line of its own.
func parseDoc(stdout string) map[string]any {
	i := strings.Index(stdout, "{")
	if i < 0 {
		return nil
	}
	var doc map[string]any
	dec := json.NewDecoder(strings.NewReader(stdout[i:]))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil
	}
	return doc
}

// freeText lists the fields whose values are implementation identity or
// free text, which the two verifiers may word differently.
var freeText = map[string]bool{
	"verifier_name":    true,
	"verifier_version": true,
	"verifier_sha256":  true,
	"failures":         true,
	"notes":            true,
	"message":          true,
}

// Compare lists every way two outcomes differ that the contract forbids:
// the exit code, the presence or absence of a document, every field of the
// document other than the identity and free-text fields, and the number
// of failures and notes. An empty result means agreement.
func Compare(php, goOut *Outcome) []string {
	var diffs []string
	if php.Exit != goOut.Exit {
		diffs = append(diffs, fmt.Sprintf("exit code: verify.php %d, sigilbase-verify %d", php.Exit, goOut.Exit))
	}
	if (php.Doc == nil) != (goOut.Doc == nil) {
		return append(diffs, fmt.Sprintf("JSON document: verify.php %v, sigilbase-verify %v", php.Doc != nil, goOut.Doc != nil))
	}
	if php.Doc == nil {
		return diffs
	}
	keys := map[string]bool{}
	for k := range php.Doc {
		keys[k] = true
	}
	for k := range goOut.Doc {
		keys[k] = true
	}
	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		a, okA := php.Doc[k]
		b, okB := goOut.Doc[k]
		if okA != okB {
			diffs = append(diffs, fmt.Sprintf("field %s: present in verify.php %v, in sigilbase-verify %v", k, okA, okB))
			continue
		}
		if k == "failures" || k == "notes" {
			la, lb := length(a), length(b)
			if la != lb {
				diffs = append(diffs, fmt.Sprintf("%s: verify.php lists %d, sigilbase-verify %d", k, la, lb))
			}
			continue
		}
		if freeText[k] {
			continue
		}
		if !reflect.DeepEqual(normalise(a), normalise(b)) {
			diffs = append(diffs, fmt.Sprintf("field %s: verify.php %s, sigilbase-verify %s", k, render(a), render(b)))
		}
	}
	return diffs
}

func length(v any) int {
	if l, ok := v.([]any); ok {
		return len(l)
	}
	return -1
}

// normalise makes PHP's empty-array-for-empty-object quirk compare equal
// to an empty object, and json.Number compare by value.
func normalise(v any) any {
	switch t := v.(type) {
	case []any:
		if len(t) == 0 {
			return map[string]any{}
		}
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normalise(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = normalise(e)
		}
		return out
	case json.Number:
		return t.String()
	}
	return v
}

func render(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Expected is one fixture's recorded expectation.
type Expected struct {
	Result  string            `json:"result"`
	Exit    int               `json:"exit"`
	Options []string          `json:"options"`
	Results map[string]string `json:"results"`
}

// ConsistencyFixture is a recorded consistency expectation: two bundles,
// or one bundle with a recorded root and size, or both.
type ConsistencyFixture struct {
	Old      string   `json:"old"`
	New      string   `json:"new"`
	Bundle   string   `json:"bundle"`
	Root     string   `json:"root"`
	Size     int64    `json:"size"`
	Result   string   `json:"result"`
	Exit     int      `json:"exit"`
	Options  []string `json:"options"`
	HasOpts  bool     `json:"-"`
	ProofNds *int     `json:"proof_nodes"`
}

// ReceiptCase is a recorded --receipt expectation (format 1.7, verifier
// 1.8): a receipt and the bundles it is checked against, the reason code
// of the first failed check (nil for none) and the receipt's subject.
type ReceiptCase struct {
	Receipt string            `json:"receipt"`
	Bundles []string          `json:"bundles"`
	Options []string          `json:"options"`
	Result  string            `json:"result"`
	Exit    int               `json:"exit"`
	Results map[string]string `json:"results"`
	Reason  *string           `json:"reason"`
	Subject string            `json:"subject"`
}

// ReconcileCase is a recorded --reconcile expectation: a registry bundle,
// its decision log, optionally a receipts directory, the reason code, the
// decision count and the number of receipts checked.
type ReconcileCase struct {
	Registry        string            `json:"registry"`
	Log             string            `json:"log"`
	Receipts        string            `json:"receipts"`
	Result          string            `json:"result"`
	Exit            int               `json:"exit"`
	Results         map[string]string `json:"results"`
	Reason          *string           `json:"reason"`
	Decisions       int64             `json:"decisions"`
	ReceiptsChecked int64             `json:"receipts_checked"`
}

// Expected returns the case's verdict expectation.
func (c *ReceiptCase) Expected() *Expected {
	return &Expected{Result: c.Result, Exit: c.Exit, Results: c.Results}
}

// Expected returns the case's verdict expectation.
func (c *ReconcileCase) Expected() *Expected {
	return &Expected{Result: c.Result, Exit: c.Exit, Results: c.Results}
}

// Corpus is corpus/expected.json.
type Corpus struct {
	DefaultOptions []string                       `json:"default_options"`
	Fixtures       map[string]*Expected           `json:"fixtures"`
	Consistency    map[string]*ConsistencyFixture `json:"consistency"`
	ReceiptOptions []string                       `json:"receipt_options"`
	Receipts       map[string]*ReceiptCase        `json:"receipts"`
	Reconcile      map[string]*ReconcileCase      `json:"reconcile"`
	rawFixtures    map[string]json.RawMessage
	rawConsistency map[string]json.RawMessage
	rawReceipts    map[string]json.RawMessage
}

// LoadCorpus reads expected.json.
func LoadCorpus(path string) (*Corpus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	var raw struct {
		Fixtures    map[string]json.RawMessage `json:"fixtures"`
		Consistency map[string]json.RawMessage `json:"consistency"`
		Receipts    map[string]json.RawMessage `json:"receipts"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	c.rawFixtures = raw.Fixtures
	c.rawConsistency = raw.Consistency
	c.rawReceipts = raw.Receipts
	return &c, nil
}

// ReceiptArgs is the command line of a receipts case, as the corpus note
// says: default_options, then the case's own options or else
// receipt_options, then --receipt <receipt> and its bundles.
func (c *Corpus) ReceiptArgs(name string) []string {
	rc := c.Receipts[name]
	args := append([]string{}, c.DefaultOptions...)
	if raw, ok := c.rawReceipts[name]; ok && bytes.Contains(raw, []byte(`"options"`)) {
		args = append(args, rc.Options...)
	} else {
		args = append(args, c.ReceiptOptions...)
	}
	args = append(args, "--receipt", rc.Receipt)
	return append(args, rc.Bundles...)
}

// ReconcileArgs is the command line of a reconcile case: default_options,
// receipt_options and --reconcile <registry> <log>, with --receipts <dir>
// when the case names one.
func (c *Corpus) ReconcileArgs(name string) []string {
	rc := c.Reconcile[name]
	args := append(append([]string{}, c.DefaultOptions...), c.ReceiptOptions...)
	args = append(args, "--reconcile", rc.Registry, rc.Log)
	if rc.Receipts != "" {
		args = append(args, "--receipts", rc.Receipts)
	}
	return args
}

// SortedReceipts lists receipts case names in order.
func (c *Corpus) SortedReceipts() []string {
	var names []string
	for n := range c.Receipts {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SortedReconcile lists reconcile case names in order.
func (c *Corpus) SortedReconcile() []string {
	var names []string
	for n := range c.Reconcile {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// CheckReceiptExpectation compares a --receipt outcome with its case: the
// verdict, the reason and the receipt's subject.
func CheckReceiptExpectation(out *Outcome, rc *ReceiptCase) []string {
	diffs := CheckExpectation(out, rc.Expected())
	if out.Doc == nil {
		return diffs
	}
	diffs = append(diffs, checkReason(out.Doc, rc.Reason)...)
	receipt, _ := out.Doc["receipt"].(map[string]any)
	if got, _ := receipt["subject"].(string); got != rc.Subject {
		diffs = append(diffs, fmt.Sprintf("receipt.subject %q, expected %q", got, rc.Subject))
	}
	return diffs
}

// CheckReconcileExpectation compares a --reconcile outcome with its case:
// the verdict, the reason, counts.decisions and receipts_checked.
func CheckReconcileExpectation(out *Outcome, rc *ReconcileCase) []string {
	diffs := CheckExpectation(out, rc.Expected())
	if out.Doc == nil {
		return diffs
	}
	diffs = append(diffs, checkReason(out.Doc, rc.Reason)...)
	counts, _ := out.Doc["counts"].(map[string]any)
	if got := numberString(counts["decisions"]); got != fmt.Sprint(rc.Decisions) {
		diffs = append(diffs, fmt.Sprintf("counts.decisions %s, expected %d", got, rc.Decisions))
	}
	if got := numberString(out.Doc["receipts_checked"]); got != fmt.Sprint(rc.ReceiptsChecked) {
		diffs = append(diffs, fmt.Sprintf("receipts_checked %s, expected %d", got, rc.ReceiptsChecked))
	}
	return diffs
}

func checkReason(doc map[string]any, want *string) []string {
	got, present := doc["reason"]
	if !present {
		return []string{"no reason field"}
	}
	switch {
	case want == nil && got != nil:
		return []string{fmt.Sprintf("reason %v, expected null", got)}
	case want != nil && got != *want:
		return []string{fmt.Sprintf("reason %v, expected %q", got, *want)}
	}
	return nil
}

func numberString(v any) string {
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	return fmt.Sprint(v)
}

// KeyOrder returns the member names of the object at the given path in a
// --json document, in the order the document writes them, so that the
// order of first appearance (which a decoded map loses) can be compared.
// Nil when the path does not lead to an object.
func KeyOrder(stdout string, path ...string) []string {
	i := strings.Index(stdout, "{")
	if i < 0 {
		return nil
	}
	raw := json.RawMessage(stdout[i:])
	dec := json.NewDecoder(strings.NewReader(stdout[i:]))
	if err := dec.Decode(&raw); err != nil {
		return nil
	}
	for _, key := range path {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil
		}
		next, ok := obj[key]
		if !ok {
			return nil
		}
		raw = next
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	keys := []string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		key, _ := tok.(string)
		keys = append(keys, key)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil
		}
	}
	return keys
}

// CompareCountOrder holds the reconcile counts to the same order of first
// appearance in both documents: the outcomes, the credentials, and each
// credential's outcomes.
func CompareCountOrder(php, goOut *Outcome) []string {
	var diffs []string
	check := func(path ...string) []string {
		a, b := KeyOrder(php.Stdout, path...), KeyOrder(goOut.Stdout, path...)
		if !reflect.DeepEqual(a, b) {
			diffs = append(diffs, fmt.Sprintf("order of %s: verify.php %v, sigilbase-verify %v", strings.Join(path, "."), a, b))
		}
		return a
	}
	check("counts", "outcomes")
	for _, credential := range check("counts", "credentials") {
		check("counts", "credentials", credential)
	}
	return diffs
}

// OptionsFor returns the options a fixture runs with: its own "options"
// when the entry carries that key (even an empty list), the defaults
// otherwise.
func (c *Corpus) OptionsFor(name string) []string {
	if raw, ok := c.rawFixtures[name]; ok && bytes.Contains(raw, []byte(`"options"`)) {
		return c.Fixtures[name].Options
	}
	return c.DefaultOptions
}

// ConsistencyOptionsFor is OptionsFor for consistency fixtures.
func (c *Corpus) ConsistencyOptionsFor(name string) []string {
	if raw, ok := c.rawConsistency[name]; ok && bytes.Contains(raw, []byte(`"options"`)) {
		return c.Consistency[name].Options
	}
	return c.DefaultOptions
}

// SortedFixtures lists fixture names in order.
func (c *Corpus) SortedFixtures() []string {
	var names []string
	for n := range c.Fixtures {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SortedConsistency lists consistency fixture names in order.
func (c *Corpus) SortedConsistency() []string {
	var names []string
	for n := range c.Consistency {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// CheckExpectation compares an outcome with the recorded expectation.
func CheckExpectation(out *Outcome, exp *Expected) []string {
	var diffs []string
	if out.Exit != exp.Exit {
		diffs = append(diffs, fmt.Sprintf("exit %d, expected %d", out.Exit, exp.Exit))
	}
	if out.Doc == nil {
		return append(diffs, "no JSON document")
	}
	if got, _ := out.Doc["result"].(string); got != exp.Result {
		diffs = append(diffs, fmt.Sprintf("result %q, expected %q", got, exp.Result))
	}
	if exp.Results != nil {
		results, _ := out.Doc["results"].(map[string]any)
		for k, want := range exp.Results {
			if got, _ := results[k].(string); got != want {
				diffs = append(diffs, fmt.Sprintf("results.%s %q, expected %q", k, got, want))
			}
		}
	}
	return diffs
}
