// Command mutate is the mutation differential: a seeded, deterministic
// mutator takes each passing corpus fixture and applies byte flips,
// truncations, line swaps, line duplication, field removal and zip entry
// edits; both verifiers run on every mutant and must agree, and no mutant
// that changes hashed content may PASS. CI runs a fixed budget and the
// nightly job a larger one. Every disagreement is written out as a bundle
// so it can become a permanent fixture.
//
//	go run ./tools/mutate -php php -go ./sigilbase-verify -budget 300 -seed 1
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/internal/difftest"
)

// hashed lists the files whose content the verdict must depend on: a
// change to any of them that survives parsing must not PASS.
//
// consistency.json and anchors.json are deliberately absent. Both are
// optional, and both verifiers treat a copy that does not parse, or that
// no longer carries its list, exactly as an absent file (FORMAT.md,
// "Verifier behaviour"): the recorded states are checked only when they
// are there to check. A mutant of either that still parses to different
// values is caught by the checks themselves, which the corpus pins.
var hashed = map[string]bool{
	"events.ndjson":           true,
	"checkpoints.json":        true,
	"declarations.ndjson":     true,
	"declaration_proofs.json": true,
}

type files map[string][]byte

type mutant struct {
	kind    string
	file    string
	entries []zipEntry
}

type zipEntry struct {
	name string
	data []byte
	dir  bool
}

func readZip(path string) ([]zipEntry, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []zipEntry
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, "/") {
			out = append(out, zipEntry{name: f.Name, dir: true})
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		buf.ReadFrom(rc)
		rc.Close()
		out = append(out, zipEntry{name: f.Name, data: buf.Bytes()})
	}
	return out, nil
}

func writeZip(path string, entries []zipEntry) error {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	epoch := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: epoch}
		if e.dir {
			hdr.Method = zip.Store
		}
		fw, err := w.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if !e.dir {
			fw.Write(e.data)
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func cloneEntries(entries []zipEntry) []zipEntry {
	out := make([]zipEntry, len(entries))
	for i, e := range entries {
		out[i] = zipEntry{name: e.name, data: append([]byte{}, e.data...), dir: e.dir}
	}
	return out
}

// mutate produces one mutant of the entries under rng.
func mutate(rng *rand.Rand, entries []zipEntry) mutant {
	// Pick a content file the format reads; verify.php and README.txt are
	// ignored by both verifiers and would only produce trivial passes.
	var candidates []int
	for i, e := range entries {
		if !e.dir && e.name != "verify.php" && e.name != "README.txt" && len(e.data) > 0 {
			candidates = append(candidates, i)
		}
	}
	out := cloneEntries(entries)
	idx := candidates[rng.Intn(len(candidates))]
	target := &out[idx]
	kind := []string{"byte-flip", "truncate", "line-swap", "line-duplicate", "field-remove", "zip-entry"}[rng.Intn(6)]
	switch kind {
	case "byte-flip":
		i := rng.Intn(len(target.data))
		target.data[i] ^= byte(1 << uint(rng.Intn(8)))
		if target.data[i] == 0 {
			target.data[i] = 'x'
		}
	case "truncate":
		target.data = target.data[:rng.Intn(len(target.data))]
	case "line-swap", "line-duplicate":
		ls := strings.Split(strings.TrimSuffix(string(target.data), "\n"), "\n")
		if len(ls) < 2 {
			return mutate(rng, entries)
		}
		a, b := rng.Intn(len(ls)), rng.Intn(len(ls))
		if kind == "line-swap" {
			ls[a], ls[b] = ls[b], ls[a]
		} else {
			ls = append(ls[:a+1], append([]string{ls[a]}, ls[a+1:]...)...)
		}
		target.data = []byte(strings.Join(ls, "\n") + "\n")
	case "field-remove":
		if !removeField(rng, target) {
			return mutate(rng, entries)
		}
	case "zip-entry":
		switch rng.Intn(4) {
		case 0: // drop the entry
			out = append(out[:idx], out[idx+1:]...)
		case 1: // duplicate the entry with a flipped byte, placed last
			dup := zipEntry{name: target.name, data: append([]byte{}, target.data...)}
			dup.data[rng.Intn(len(dup.data))] ^= 0x01
			out = append(out, dup)
		case 2: // shadow it through a parent path
			dup := zipEntry{name: "../" + target.name, data: append([]byte{}, target.data...)}
			dup.data[rng.Intn(len(dup.data))] ^= 0x01
			out = append(out, dup)
		case 3: // rename it away
			target.name = target.name + ".bak"
		}
	}
	return mutant{kind: kind, file: entries[idx].name, entries: out}
}

// removeField deletes one key from a random object in a JSON file or in a
// random line of an ndjson file, re-emitting the document compactly.
func removeField(rng *rand.Rand, target *zipEntry) bool {
	if strings.HasSuffix(target.name, ".ndjson") {
		ls := strings.Split(strings.TrimSuffix(string(target.data), "\n"), "\n")
		i := rng.Intn(len(ls))
		edited, ok := removeFieldFromDocument(rng, []byte(ls[i]))
		if !ok {
			return false
		}
		ls[i] = string(edited)
		target.data = []byte(strings.Join(ls, "\n") + "\n")
		return true
	}
	if !strings.HasSuffix(target.name, ".json") {
		return false
	}
	edited, ok := removeFieldFromDocument(rng, target.data)
	if !ok {
		return false
	}
	target.data = edited
	return true
}

func removeFieldFromDocument(rng *rand.Rand, data []byte) ([]byte, bool) {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	var objects []map[string]any
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if len(t) > 0 {
				objects = append(objects, t)
			}
			for _, e := range t {
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(doc)
	if len(objects) == 0 {
		return nil, false
	}
	obj := objects[rng.Intn(len(objects))]
	var keys []string
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	delete(obj, keys[rng.Intn(len(keys))])
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
}

// unverified lists, per file, the fields no hash or check covers, so a
// mutant that changes only them may legitimately PASS: the v of an event
// or checkpoint (both preimages fix v to 1), a checkpoint's own stream
// field (the manifest's stream is hashed), and a declaration's slug and
// state fields. FORMAT.md records each.
var unverified = map[string][]string{
	"events.ndjson":       {"v", "payload_state"},
	"checkpoints.json":    {"v", "stream"},
	"declarations.ndjson": {"v", "stream_slug", "payload_state", "absence"},
}

// isHex reports whether a string is hexadecimal of a hash-like length.
func isHex(s string) bool {
	if len(s) < 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func stripUnverified(v *cjson.Value, name string) {
	if v == nil {
		return
	}
	switch v.Kind {
	case cjson.String:
		// Hashes, signatures and keys are compared lowercased (FORMAT.md,
		// "Field types"), so a change of case alone is not a change.
		if isHex(v.Str) {
			v.Str = strings.ToLower(v.Str)
		}
	case cjson.Object:
		for _, k := range unverified[name] {
			v.Obj.Delete(k)
		}
		for _, k := range v.Obj.Keys() {
			child, _ := v.Obj.Get(k)
			stripUnverified(child, name)
		}
	case cjson.Array:
		for _, e := range v.Arr {
			stripUnverified(e, name)
		}
	}
}

// semanticallySame reports whether a mutated hashed file still decodes to
// the same verified values as the original: a byte flip inside JSON
// whitespace, a field removal that only touched indentation, or a change
// to a field no check covers, changes nothing the verdict depends on, so
// such a mutant may legitimately PASS.
func semanticallySame(name string, before, after []byte) bool {
	if bytes.Equal(before, after) {
		return true
	}
	canon := func(data []byte) (string, bool) {
		if strings.HasSuffix(name, ".ndjson") {
			var parts []string
			for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
				if strings.TrimSpace(l) == "" {
					continue
				}
				v, err := cjson.Parse([]byte(l))
				if err != nil {
					return "", false
				}
				stripUnverified(v, name)
				c, err := cjson.Canonical(v)
				if err != nil {
					return "", false
				}
				parts = append(parts, string(c))
			}
			return strings.Join(parts, "\n"), true
		}
		v, err := cjson.Parse(data)
		if err != nil {
			return "", false
		}
		stripUnverified(v, name)
		c, err := cjson.Canonical(v)
		if err != nil {
			return "", false
		}
		return string(c), true
	}
	a, okA := canon(before)
	b, okB := canon(after)
	return okA && okB && a == b
}

func main() {
	php := flag.String("php", "php", "php binary")
	phpArgs := flag.String("php-args", "", "leading arguments for php")
	verifyPHP := flag.String("verify-php", "reference/verify.php", "path to verify.php (the reference implementation mirrored under reference/)")
	goBinary := flag.String("go", "./sigilbase-verify", "path to sigilbase-verify")
	corpusPath := flag.String("corpus", "corpus/expected.json", "expected.json")
	budget := flag.Int("budget", 300, "number of mutants to run")
	seed := flag.Int64("seed", 1, "random seed; the same seed gives the same mutants")
	outDir := flag.String("disagreements", "corpus/disagreements", "where mutants that expose a disagreement are written")
	work := flag.String("work", "", "working directory for mutant files (default: a temporary directory)")
	flag.Parse()

	runner := &difftest.Runner{PHP: *php, VerifyPHP: *verifyPHP, GoBinary: *goBinary, Dir: "."}
	if *phpArgs != "" {
		runner.PHPArgs = strings.Fields(*phpArgs)
	}
	corpus, err := difftest.LoadCorpus(*corpusPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mutate:", err)
		os.Exit(2)
	}
	dir := *work
	if dir == "" {
		dir, err = os.MkdirTemp("", "sigilbase-mutants-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "mutate:", err)
			os.Exit(2)
		}
		defer os.RemoveAll(dir)
	}

	// Seeds: every fixture recorded as passing under the default options.
	type seedFixture struct {
		name    string
		entries []zipEntry
		options []string
	}
	var seeds []seedFixture
	for _, name := range corpus.SortedFixtures() {
		exp := corpus.Fixtures[name]
		if exp.Result != "pass" || strings.Contains(name, "/") {
			continue
		}
		entries, err := readZip("corpus/" + name + ".zip")
		if err != nil {
			fmt.Fprintln(os.Stderr, "mutate:", err)
			os.Exit(2)
		}
		seeds = append(seeds, seedFixture{name: name, entries: entries, options: corpus.OptionsFor(name)})
	}

	rng := rand.New(rand.NewSource(*seed))
	disagreements := 0
	unsoundPasses := 0
	counts := map[string]int{}
	for n := 0; n < *budget; n++ {
		sf := seeds[rng.Intn(len(seeds))]
		m := mutate(rng, sf.entries)
		counts[m.kind]++
		path := filepath.Join(dir, fmt.Sprintf("mutant-%d-%d.zip", *seed, n))
		if err := writeZip(path, m.entries); err != nil {
			fmt.Fprintln(os.Stderr, "mutate:", err)
			os.Exit(2)
		}
		args := append(append([]string{}, sf.options...), path)
		phpOut, err := runner.RunPHP(args...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mutate:", err)
			os.Exit(2)
		}
		goOut, err := runner.RunGo(args...)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mutate:", err)
			os.Exit(2)
		}
		problems := difftest.Compare(phpOut, goOut)
		if phpOut.Exit == 0 && hashed[m.file] && m.kind != "zip-entry" {
			var before []byte
			for _, e := range sf.entries {
				if e.name == m.file {
					before = e.data
				}
			}
			var after []byte
			found := false
			for _, e := range m.entries {
				if e.name == m.file {
					after = e.data
					found = true
				}
			}
			if found && !semanticallySame(m.file, before, after) {
				unsoundPasses++
				problems = append(problems, "a mutant of hashed content PASSED in both verifiers")
			}
		}
		if len(problems) == 0 {
			os.Remove(path)
			continue
		}
		disagreements++
		os.MkdirAll(*outDir, 0o755)
		kept := filepath.Join(*outDir, fmt.Sprintf("%s-seed%d-%d-%s.zip", sf.name, *seed, n, m.kind))
		os.Rename(path, kept)
		fmt.Printf("DISAGREE %s (%s of %s from %s), kept as %s\n", kept, m.kind, m.file, sf.name, kept)
		for _, p := range problems {
			fmt.Printf("         %s\n", p)
		}
	}
	fmt.Printf("ran %d mutants with seed %d over %d seed fixtures: %v\n", *budget, *seed, len(seeds), counts)
	if disagreements > 0 {
		fmt.Printf("%d disagreement(s), %d unsound pass(es). Each kept mutant must become a permanent fixture.\n", disagreements, unsoundPasses)
		os.Exit(1)
	}
	fmt.Println("every mutant agrees and no mutant of hashed content passed")
}
