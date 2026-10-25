package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigilbase/verifier-go/internal/difftest"
	"github.com/sigilbase/verifier-go/keys"
)

// The conformance corpus is the executable specification: every fixture in
// corpus/expected.json must produce the recorded exit code, overall result
// and per-result states. verify.php is held to the same file by the
// differential job.
func TestCorpusExpectations(t *testing.T) {
	corpus, err := difftest.LoadCorpus("../corpus/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range corpus.SortedFixtures() {
		exp := corpus.Fixtures[name]
		opts, path := optionsFromArgs(t, corpus.OptionsFor(name), "../corpus/"+name+".zip")
		rep := Bundle(path, opts)
		checkReport(t, name, rep, exp)
	}
}

func TestCorpusConsistencyExpectations(t *testing.T) {
	corpus, err := difftest.LoadCorpus("../corpus/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range corpus.SortedConsistency() {
		fx := corpus.Consistency[name]
		exp := &difftest.Expected{Result: fx.Result, Exit: fx.Exit}
		if fx.Old != "" && fx.New != "" {
			opts, _ := optionsFromArgs(t, corpus.ConsistencyOptionsFor(name), "")
			rep := ConsistencyBundles("../corpus/"+fx.Old+".zip", "../corpus/"+fx.New+".zip", opts)
			checkReport(t, name+" (two bundles)", rep, exp)
			if fx.ProofNds != nil && (rep.Consistency == nil || rep.Consistency.ProofNodes != *fx.ProofNds) {
				t.Errorf("%s: proof nodes %v, expected %d", name, rep.Consistency, *fx.ProofNds)
			}
		}
		if fx.Bundle != "" && fx.Root != "" {
			opts, _ := optionsFromArgs(t, corpus.ConsistencyOptionsFor(name), "")
			rep := ConsistencyRecorded("../corpus/"+fx.Bundle+".zip", fx.Root, fx.Size, opts)
			checkReport(t, name+" (recorded root)", rep, exp)
		}
	}
}

// The receipts and reconcile cases (format 1.7, verifier 1.8) run with the
// command lines the corpus note describes, and must produce the recorded
// verdict, reason, subject, decision count and receipts checked.
func TestCorpusReceiptExpectations(t *testing.T) {
	corpus, err := difftest.LoadCorpus("../corpus/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.Receipts) == 0 {
		t.Fatal("expected.json has no receipts cases")
	}
	for _, name := range corpus.SortedReceipts() {
		rc := corpus.Receipts[name]
		rep := runCorpusArgs(t, corpus.ReceiptArgs(name))
		checkReport(t, "receipt "+name, rep, rc.Expected())
		checkReason(t, "receipt "+name, rep, rc.Reason)
		if rep.Receipt == nil || rep.Receipt.Subject != rc.Subject {
			t.Errorf("receipt %s: subject %+v, expected %q", name, rep.Receipt, rc.Subject)
		}
	}
}

func TestCorpusReconcileExpectations(t *testing.T) {
	corpus, err := difftest.LoadCorpus("../corpus/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.Reconcile) == 0 {
		t.Fatal("expected.json has no reconcile cases")
	}
	for _, name := range corpus.SortedReconcile() {
		rc := corpus.Reconcile[name]
		rep := runCorpusArgs(t, corpus.ReconcileArgs(name))
		checkReport(t, "reconcile "+name, rep, rc.Expected())
		checkReason(t, "reconcile "+name, rep, rc.Reason)
		if rep.Counts == nil || rep.Counts.Decisions != rc.Decisions {
			t.Errorf("reconcile %s: counts %+v, expected %d decisions", name, rep.Counts, rc.Decisions)
		}
		if int64(rep.ReceiptsChecked) != rc.ReceiptsChecked {
			t.Errorf("reconcile %s: %d receipts checked, expected %d", name, rep.ReceiptsChecked, rc.ReceiptsChecked)
		}
	}
}

// The counts keep the order in which outcomes and credentials first
// appear in the log, and an empty map is written as {} (verify.php casts
// each to an object).
func TestReconcileCountsDocument(t *testing.T) {
	corpus, err := difftest.LoadCorpus("../corpus/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	rep := runCorpusArgs(t, corpus.ReconcileArgs("valid"))
	doc, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if got := difftest.KeyOrder(string(doc), "counts", "outcomes"); strings.Join(got, ",") != "accepted,replay,conflict,invalid,refused_early,refused_late" {
		t.Errorf("outcomes in order %v", got)
	}
	if got := difftest.KeyOrder(string(doc), "counts", "credentials"); strings.Join(got, ",") != "sgb_filer000000001,sgb_second00000002" {
		t.Errorf("credentials in order %v", got)
	}
	empty := runCorpusArgs(t, corpus.ReconcileArgs("swapped-bundles"))
	doc, err = empty.JSON()
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(string(doc)), "")
	if !strings.Contains(compact, `"counts":{"decisions":0,"outcomes":{},"credentials":{}}`) {
		t.Errorf("empty counts written as %s", compact)
	}
}

func checkReason(t *testing.T, name string, rep *Report, want *string) {
	t.Helper()
	switch {
	case want == nil && rep.Reason != nil:
		t.Errorf("%s: reason %s, expected null", name, *rep.Reason)
	case want != nil && (rep.Reason == nil || *rep.Reason != *want):
		t.Errorf("%s: reason %v, expected %s", name, rep.Reason, *want)
	}
}

// runCorpusArgs runs a receipts or reconcile command line from the corpus
// through the library, resolving paths against the repository root.
func runCorpusArgs(t *testing.T, args []string) *Report {
	t.Helper()
	var opts []string
	var receipt, receiptsDir *string
	reconcile := false
	var targets []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--receipt":
			i++
			p := "../" + args[i]
			receipt = &p
		case "--receipts":
			i++
			p := "../" + args[i]
			receiptsDir = &p
		case "--reconcile":
			reconcile = true
		case "--keys", "--tsa-roots", "--receipt-keys":
			opts = append(opts, args[i], args[i+1])
			i++
		default:
			if strings.HasPrefix(args[i], "--") {
				opts = append(opts, args[i])
			} else {
				targets = append(targets, "../"+args[i])
			}
		}
	}
	o, _ := optionsFromArgs(t, opts, "")
	if reconcile {
		if len(targets) != 2 {
			t.Fatalf("reconcile case with %d bundles", len(targets))
		}
		return Reconcile(targets[0], targets[1], receiptsDir, o)
	}
	if receipt == nil {
		t.Fatal("receipts case without --receipt")
	}
	return Receipt(*receipt, targets, o)
}

// optionsFromArgs turns a fixture's recorded command-line options into
// Options, resolving file arguments relative to the repository root.
func optionsFromArgs(t *testing.T, args []string, bundlePath string) (Options, string) {
	t.Helper()
	var opts Options
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--receipt-keys":
			i++
			set, err := LoadReceiptKeyFile("../" + args[i])
			if err != nil {
				t.Fatal(err)
			}
			opts.ReceiptKeys = set
			opts.ReceiptKeysSource = "--receipt-keys " + args[i]
		case "--keys":
			i++
			set, err := LoadKeyFile("../" + args[i])
			if err != nil {
				t.Fatal(err)
			}
			opts.Keys = set
			opts.KeysSource = "--keys " + args[i]
		case "--tsa-roots":
			i++
			data, err := os.ReadFile("../" + args[i])
			if err != nil {
				t.Fatal(err)
			}
			pem := string(data)
			opts.TSARoots = &pem
			opts.TSARootsSource = "--tsa-roots " + args[i]
		case "--skip-anchors":
			opts.SkipAnchors = true
		case "--print-hashes":
			opts.PrintHashes = true
		default:
			t.Fatalf("unsupported option in expected.json: %s", args[i])
		}
	}
	return opts, bundlePath
}

func checkReport(t *testing.T, name string, rep *Report, exp *difftest.Expected) {
	t.Helper()
	if rep.ExitCode != exp.Exit {
		t.Errorf("%s: exit %d, expected %d (%s)", name, rep.ExitCode, exp.Exit, rep.Message)
	}
	if rep.Result != exp.Result {
		t.Errorf("%s: result %q, expected %q", name, rep.Result, exp.Result)
	}
	for k, want := range exp.Results {
		if rep.Results == nil || rep.Results.Get(k) != want {
			t.Errorf("%s: results.%s %q, expected %q", name, k, rep.Results.Get(k), want)
		}
	}
	// The document must round-trip through the schema's shape.
	doc, err := rep.JSON()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("%s: report is not valid JSON: %v", name, err)
	}
	for _, field := range []string{"verifier_name", "verifier_version", "result", "exit_code"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("%s: document lacks %s", name, field)
		}
	}
}

// A production bundle from the exporter, verified with the embedded trust
// material and nothing else, is the assessor's first experience: the
// timestamps must be confirmed by the built-in TSA roots rather than
// reported as unconfirmed (decision D3).
func TestEmbeddedRootsConfirmProductionAnchors(t *testing.T) {
	path := os.Getenv("SIGILBASE_PRODUCTION_BUNDLE")
	if path == "" {
		t.Skip("set SIGILBASE_PRODUCTION_BUNDLE to a bundle anchored by FreeTSA and DFN-Verein")
	}
	rep := Bundle(path, Options{})
	if rep.Results.Get(ResultTimestamps) != StatePass {
		t.Errorf("timestamps %s with the embedded roots; notes: %v", rep.Results.Get(ResultTimestamps), rep.Notes)
	}
}

// The embedded trust material must be the files in keys/ at the tag, byte
// for byte: "which keys does this verifier trust" has one answer per
// release, and tools/compile-keys.php holds verify.php to the same files.
func TestEmbeddedKeyFilesMatchRepository(t *testing.T) {
	for name, embedded := range map[string][]byte{"sigilbase.json": keys.SigilbaseJSON, "tsa-roots.pem": keys.TSARootsPEM, "receipt-keys.json": keys.ReceiptKeysJSON} {
		onDisk, err := os.ReadFile(filepath.Join("..", "keys", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(onDisk, embedded) {
			t.Errorf("keys/%s differs from the embedded copy: %s vs %s", name, sumOf(onDisk), sumOf(embedded))
		}
		if bytes.Contains(onDisk, []byte("\r")) {
			t.Errorf("keys/%s contains a carriage return; the file is hash-compared across platforms", name)
		}
	}
	set := EmbeddedKeys()
	for _, k := range set.entries {
		raw, ok := hexBytes(k.publicKey)
		if !ok || len(raw) != 32 {
			t.Errorf("embedded key %q is not a 32-byte hex public key", k.publicKey)
		}
	}
	// Every embedded receipt key's key_id is the SHA-256 of its key, or the
	// set would not load at all (EmbeddedReceiptKeys panics).
	_ = EmbeddedReceiptKeys()
}

// A --receipt-keys entry whose key_id is not the SHA-256 of its public key
// is an error in the file, as is a file without a keys list; an empty list
// is a valid (empty) set.
func TestReceiptKeyFileRules(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const pk = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
	const id = "dac073e0123bdea59dd9b3bda9cf6037f63aca82627d7abcd5c4ac29dd74003e"
	if _, err := LoadReceiptKeyFile(write("bad.json", `{"keys":[{"key_id":"`+strings.Repeat("0", 64)+`","public_key":"`+pk+`"}]}`)); err == nil || !strings.Contains(err.Error(), "is not the SHA-256 of its public_key") {
		t.Errorf("mismatched key_id: %v", err)
	}
	if _, err := LoadReceiptKeyFile(write("none.json", `{"nokeys":[]}`)); err == nil || !strings.Contains(err.Error(), `has no "keys" list`) {
		t.Errorf("no keys list: %v", err)
	}
	if _, err := LoadReceiptKeyFile(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing file: %v", err)
	}
	set, err := LoadReceiptKeyFile(write("empty.json", `{"keys":[]}`))
	if err != nil || set.Len() != 0 {
		t.Errorf("empty list: %v %v", set, err)
	}
	set, err = LoadReceiptKeyFile(write("upper.json", `{"keys":[{"key_id":"`+strings.ToUpper(id)+`","public_key":"`+strings.ToUpper(pk)+`"}]}`))
	if err != nil || set.Len() != 1 || set.keys[id].publicKey != pk {
		t.Errorf("upper-case hex: %v %v", set, err)
	}
}

func sumOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// The verifier makes no network calls of any kind, runs no other program,
// loads no plugin, and touches no memory unsafely. This walks the import
// graph of the binary, package by package within this module, and fails on
// the first forbidden import. The system certificate store is checked
// separately below.
func TestImportGraphHasNoNetworkOrExecOrUnsafe(t *testing.T) {
	forbidden := map[string]bool{"net/http": true, "os/exec": true, "plugin": true, "unsafe": true, "net": true}
	const module = "github.com/sigilbase/verifier-go"
	seen := map[string]bool{}
	var walk func(pkg string)
	walk = func(pkg string) {
		if seen[pkg] {
			return
		}
		seen[pkg] = true
		dir := filepath.Join("..", filepath.FromSlash(strings.TrimPrefix(pkg, module+"/")))
		if pkg == module {
			dir = ".."
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", pkg, err)
		}
		fset := token.NewFileSet()
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, "\"")
				if forbidden[p] {
					t.Errorf("%s (%s) imports %s", pkg, name, p)
				}
				if strings.HasPrefix(p, module+"/") {
					walk(p)
				}
			}
		}
	}
	walk(module + "/cmd/sigilbase-verify")
	for _, want := range []string{module + "/verify", module + "/internal/cjson", module + "/internal/tst", module + "/internal/bundle", module + "/keys"} {
		if !seen[want] {
			t.Errorf("%s not reached from the command; the walk is incomplete", want)
		}
	}
}

// Trust comes from the embedded roots or from --tsa-roots and from nowhere
// else: the operating system's certificate store is never consulted, and
// crypto/x509 (which would make that a one-line change) is never imported.
func TestSystemCertPoolNeverAppears(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "verify_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(src, []byte("SystemCertPool")) {
			t.Errorf("%s refers to the system certificate store", path)
		}
		f, err := parser.ParseFile(fset, path, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, "\"") == "crypto/x509" {
				t.Errorf("%s imports crypto/x509", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// PHP-cast helpers, pinned to the observed PHP behaviour.
func TestPHPHelpers(t *testing.T) {
	if lower("ABCÉ") != "abcÉ" {
		t.Error("strtolower must be ASCII-only")
	}
	if keyFingerprint("") != "e3b0c44298fc1c14" || keyFingerprint("a") != "unreadable" || keyFingerprint("zz") != "unreadable" {
		t.Error("key_fingerprint edge cases")
	}
	if keyFingerprint("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a") != "21fe31dfa154a261" {
		t.Error("corpus key fingerprint")
	}
	if phpFloatString(1e30) != "1.0E+30" || phpFloatString(1.5) != "1.5" || phpFloatString(math.Copysign(0, -1)) != "-0" || phpFloatString(1.0) != "1" || phpFloatString(0.1) != "0.1" {
		t.Errorf("float strings: %s %s %s %s %s", phpFloatString(1e30), phpFloatString(1.5), phpFloatString(math.Copysign(0, -1)), phpFloatString(1.0), phpFloatString(0.1))
	}
}
