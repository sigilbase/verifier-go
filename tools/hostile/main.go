// Command hostile builds the corpus/hostile fixtures: bundles derived from
// the conformance corpus that each pin one rule of FORMAT.md's "Parsing"
// and "Ed25519 acceptance" sections, or one crash that verify.php 1.5.0
// suffered on a hostile field type. Every fixture is deterministic (fixed
// entry times, fixed compression) and the tool is idempotent, so CI can
// regenerate the set and diff it against the committed files.
//
// Fixtures that need a valid signature over altered content are re-signed
// under the published corpus test key (corpus/test-signing-key.txt), which
// signs nothing else.
//
//	go run ./tools/hostile
package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/internal/merkle"
)

const seedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

type files map[string][]byte

func readZip(path string) files {
	r, err := zip.OpenReader(path)
	if err != nil {
		fatal(err)
	}
	defer r.Close()
	out := files{}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			fatal(err)
		}
		var buf bytes.Buffer
		buf.ReadFrom(rc)
		rc.Close()
		out[f.Name] = buf.Bytes()
	}
	return out
}

func (f files) clone() files {
	out := files{}
	for k, v := range f {
		out[k] = append([]byte{}, v...)
	}
	return out
}

type entry struct {
	name string
	data []byte
	dir  bool
}

func ordered(f files) []entry {
	var names []string
	for n := range f {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []entry
	for _, n := range names {
		out = append(out, entry{name: n, data: f[n]})
	}
	return out
}

var epoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

func writeZip(path string, entries []entry) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		name := e.name
		if e.dir {
			name = strings.TrimSuffix(name, "/") + "/"
		}
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: epoch}
		if e.dir {
			hdr.Method = zip.Store
		}
		fw, err := w.CreateHeader(hdr)
		if err != nil {
			fatal(err)
		}
		if !e.dir {
			fw.Write(e.data)
		}
	}
	if err := w.Close(); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "hostile:", err)
	os.Exit(2)
}

// lines splits events.ndjson into its lines without the trailing newline.
func lines(data []byte) []string {
	s := strings.TrimSuffix(string(data), "\n")
	return strings.Split(s, "\n")
}

func joinLines(ls []string) []byte { return []byte(strings.Join(ls, "\n") + "\n") }

// replaceOnce replaces exactly one occurrence or fails, so a fixture never
// silently pins the wrong thing.
func replaceOnce(data []byte, old, new string) []byte {
	if bytes.Count(data, []byte(old)) != 1 {
		fatal(fmt.Errorf("expected exactly one %q", old))
	}
	return bytes.Replace(data, []byte(old), []byte(new), 1)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func canonical(v *cjson.Value) []byte {
	out, err := cjson.Canonical(v)
	if err != nil {
		fatal(err)
	}
	return out
}

func parse(data []byte) *cjson.Value {
	v, err := cjson.Parse(data)
	if err != nil {
		fatal(err)
	}
	return v
}

func str(s string) *cjson.Value { return &cjson.Value{Kind: cjson.String, Str: s} }
func integer(n int64) *cjson.Value {
	return &cjson.Value{Kind: cjson.Int, Int: n}
}

// resignLastEvent rewrites the last event of a valid bundle through
// mutate, recomputes its payload and entry hashes, and re-seals the
// checkpoint covering it. consistency.json is dropped: its recorded roots
// and proof would need rebuilding too, and the file is optional.
func resignLastEvent(f files, mutate func(ev *cjson.Value)) files {
	out := f.clone()
	delete(out, "consistency.json")
	ls := lines(out["events.ndjson"])
	last := parse([]byte(ls[len(ls)-1]))
	mutate(last)
	payload := last.Field("payload")
	if payload == nil {
		payload = &cjson.Value{Kind: cjson.Null}
	}
	last.Obj.Set("payload_hash", str(sha256Hex(canonical(payload))))
	manifest := parse(out["manifest.json"])
	stream := manifest.Field("stream").Field("id").Str
	pre := cjson.NewObject()
	pre.Set("v", integer(1))
	pre.Set("stream", str(stream))
	pre.Set("seq", last.Field("seq"))
	for _, k := range []string{"occurred_at", "received_at", "actor", "action", "resource", "payload_hash"} {
		pre.Set(k, last.Field(k))
	}
	pre.Set("prev", last.Field("prev_hash"))
	last.Obj.Set("entry_hash", str(sha256Hex(canonical(&cjson.Value{Kind: cjson.Object, Obj: pre}))))
	ls[len(ls)-1] = string(canonical(last))
	out["events.ndjson"] = joinLines(ls)

	// Re-seal the last checkpoint.
	var doc map[string]any
	json.Unmarshal(out["checkpoints.json"], &doc)
	cps := doc["checkpoints"].([]any)
	cp := cps[len(cps)-1].(map[string]any)
	from := int(cp["from"].(float64))
	var leaves [][]byte
	for _, l := range ls[from-1:] {
		eh, _ := hex.DecodeString(parse([]byte(l)).Field("entry_hash").Str)
		leaves = append(leaves, eh)
	}
	root, _ := merkle.Root(leaves)
	cp["root"] = hex.EncodeToString(root)
	sealCheckpoint(cp, stream)
	out["checkpoints.json"] = marshalPretty(doc)
	return out
}

// sealCheckpoint recomputes a checkpoint's hash and signature under the
// corpus test key.
func sealCheckpoint(cp map[string]any, stream string) {
	pre := cjson.NewObject()
	pre.Set("v", integer(1))
	pre.Set("stream", str(stream))
	pre.Set("from", integer(int64(cp["from"].(float64))))
	pre.Set("to", integer(int64(cp["to"].(float64))))
	pre.Set("root", str(cp["root"].(string)))
	pre.Set("prev_checkpoint", str(cp["prev_checkpoint"].(string)))
	pre.Set("created_at", str(cp["created_at"].(string)))
	hash := sha256Hex(canonical(&cjson.Value{Kind: cjson.Object, Obj: pre}))
	cp["checkpoint_hash"] = hash
	seed, _ := hex.DecodeString(seedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	raw, _ := hex.DecodeString(hash)
	cp["signature"] = hex.EncodeToString(ed25519.Sign(priv, raw))
	cp["public_key"] = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func marshalPretty(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	enc.Encode(v)
	return buf.Bytes()
}

// editJSON applies fn to a parsed JSON file and writes it back pretty.
func editJSON(f files, name string, fn func(doc map[string]any)) {
	var doc map[string]any
	if err := json.Unmarshal(f[name], &doc); err != nil {
		fatal(err)
	}
	fn(doc)
	f[name] = marshalPretty(doc)
}

func firstCheckpoint(doc map[string]any) map[string]any {
	return doc["checkpoints"].([]any)[0].(map[string]any)
}

func lastCheckpoint(doc map[string]any) map[string]any {
	cps := doc["checkpoints"].([]any)
	return cps[len(cps)-1].(map[string]any)
}

// Ed25519 scalar arithmetic for the forged signatures (see
// vectors/vectors.json, "ed25519_acceptance").
var groupOrder, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

func scalarLE(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(rev)
}

func scalarBytes(s *big.Int) []byte {
	out := make([]byte, 32)
	b := s.Bytes()
	for i := 0; i < len(b); i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// smallOrderRSignature is a signature with R = the identity point that
// satisfies the verification equation under the corpus test key:
// S = H(R || A || M) * a mod l, so S*B = h*A and R = S*B - h*A = O.
func smallOrderRSignature(message []byte) []byte {
	seed, _ := hex.DecodeString(seedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	a := scalarLE(h[:32])
	R := make([]byte, 32)
	R[0] = 1
	k := sha512.New()
	k.Write(R)
	k.Write(pub)
	k.Write(message)
	hs := new(big.Int).Mod(scalarLE(k.Sum(nil)), groupOrder)
	S := new(big.Int).Mod(new(big.Int).Mul(hs, a), groupOrder)
	return append(R, scalarBytes(S)...)
}

func nonCanonicalS(sig []byte) []byte {
	S := scalarLE(sig[32:])
	S.Add(S, groupOrder)
	return append(append([]byte{}, sig[:32]...), scalarBytes(S)...)
}

func main() {
	out := flag.String("out", "corpus/hostile", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal(err)
	}
	valid := readZip("corpus/valid.zip")
	anchored := readZip("corpus/anchored.zip")
	redacted := readZip("corpus/redacted.zip")

	type fixture struct {
		name    string
		entries []entry
		doc     string
	}
	var fixtures []fixture
	add := func(name, doc string, f files) {
		fixtures = append(fixtures, fixture{name: name, entries: ordered(f), doc: doc})
	}
	addEntries := func(name, doc string, entries []entry) {
		fixtures = append(fixtures, fixture{name: name, entries: entries, doc: doc})
	}

	// --- field types that stopped verify.php 1.5.0 with a fatal error ---
	f := valid.clone()
	editJSON(f, "checkpoints.json", func(doc map[string]any) { firstCheckpoint(doc)["checkpoint_hash"] = map[string]any{} })
	add("type-object-checkpoint-hash", "checkpoint_hash is an object: FAIL (content integrity), not a fatal error", f)

	f = valid.clone()
	ls := lines(f["events.ndjson"])
	ls[0] = strings.Replace(ls[0], `"actor":"user:2"`, `"actor":1.5`, 1)
	f["events.ndjson"] = joinLines(ls)
	add("type-float-actor", "a float in a hashed event field cannot be canonicalised: FAIL", f)

	f = valid.clone()
	ls = lines(f["events.ndjson"])
	ls[0] = strings.Replace(ls[0], `"seq":1,`, `"seq":9223372036854775807,`, 1)
	f["events.ndjson"] = joinLines(ls)
	add("type-bigint-seq", "an integer beyond 2^53-1 in a hashed field cannot be canonicalised: FAIL", f)

	f = anchored.clone()
	editJSON(f, "anchors.json", func(doc map[string]any) { doc["anchors"].([]any)[0].(map[string]any)["provider"] = map[string]any{} })
	add("type-object-anchor-provider", "an object where a label string is expected: still PASS, the label is cosmetic", f)

	f = valid.clone()
	editJSON(f, "consistency.json", func(doc map[string]any) { doc["proof"].(map[string]any)["from_tree_size"] = map[string]any{} })
	add("type-object-proof-size", "an object as a proof tree size casts to 1 as PHP's (int) does: the proof fails, FAIL", f)

	f = valid.clone()
	editJSON(f, "manifest.json", func(doc map[string]any) { doc["signing_keys"] = "not-a-list" })
	add("type-scalar-signing-keys", "signing_keys is a scalar: no keys, exit 1", f)

	// --- dates ---
	f = valid.clone()
	editJSON(f, "checkpoints.json", func(doc map[string]any) { firstCheckpoint(doc)["created_at"] = "2026-13-01T00:00:00.000000Z" })
	add("date-month-13", "a created_at PHP's date parser refuses: the checkpoint hash no longer recomputes and the window cannot be checked, FAIL", f)

	f = valid.clone()
	editJSON(f, "checkpoints.json", func(doc map[string]any) {
		// The last checkpoint: nothing chains to it, so re-sealing it
		// changes no other checkpoint's prev_checkpoint.
		cp := lastCheckpoint(doc)
		cp["created_at"] = "2026-01-02T03:04:05.000000Z\n"
		sealCheckpoint(cp, parse(f["manifest.json"]).Field("stream").Field("id").Str)
	})
	add("date-trailing-newline-resigned", "the last checkpoint's created_at with one trailing newline, re-sealed: accepted by both (PCRE's $ matches before a final newline and PHP's date parser reads the value), PASS", f)

	// --- JSON parsing rules ---
	f = valid.clone()
	ls = lines(f["events.ndjson"])
	ls[len(ls)-1] = strings.Replace(ls[len(ls)-1], `{"action"`, `{"actor":"bogus","action"`, 1)
	f["events.ndjson"] = joinLines(ls)
	add("json-duplicate-keys-last-wins", "a duplicated key whose last value is the sealed one: PASS (the last value wins)", f)

	g := valid.clone()
	gl := lines(g["events.ndjson"])
	if !strings.Contains(gl[len(gl)-1], `"actor":"user:1"`) {
		fatal(fmt.Errorf("unexpected last event line"))
	}
	gl[len(gl)-1] = strings.Replace(gl[len(gl)-1], `"actor":"user:1"`, `"actor":"user:1","actor":"bogus"`, 1)
	g["events.ndjson"] = joinLines(gl)
	add("json-duplicate-keys-last-differs", "a duplicated key whose last value is not the sealed one: the last value wins, the entry hash breaks, FAIL", g)

	f = resignLastEvent(valid, func(ev *cjson.Value) {
		// The event object is the outermost container, so a payload nested
		// 510 deep makes 511 levels, the deepest PHP's default depth decodes.
		depth := 510
		var v *cjson.Value = &cjson.Value{Kind: cjson.Array}
		for i := 1; i < depth; i++ {
			v = &cjson.Value{Kind: cjson.Array, Arr: []*cjson.Value{v}}
		}
		ev.Obj.Set("payload", v)
	})
	add("json-depth-511-resigned", "a line nested 511 containers deep (the event object plus a 510-deep payload), re-sealed: PASS (the deepest nesting PHP decodes)", f)

	f = valid.clone()
	ls = lines(f["events.ndjson"])
	ls[len(ls)-1] = strings.Replace(ls[len(ls)-1], `"payload":{"n":40}`, `"payload":`+strings.Repeat("[", 511)+strings.Repeat("]", 511), 1)
	f["events.ndjson"] = joinLines(ls)
	add("json-depth-512", "a line nested 512 containers deep: it does not parse, FAIL", f)

	f = valid.clone()
	f["events.ndjson"] = append([]byte{0xEF, 0xBB, 0xBF}, f["events.ndjson"]...)
	add("json-bom-events", "a byte order mark before the first line: that line does not parse, FAIL", f)

	f = valid.clone()
	f["manifest.json"] = append([]byte{0xEF, 0xBB, 0xBF}, f["manifest.json"]...)
	add("json-bom-manifest", "a byte order mark before manifest.json: unknown format, ERROR (exit 2)", f)

	f = valid.clone()
	ls = lines(f["events.ndjson"])
	ls[len(ls)-1] = strings.Replace(ls[len(ls)-1], `"payload":{"n":40}`, `"payload":{"n":40,"s":"`+"\\"+`ud800"}`, 1)
	f["events.ndjson"] = joinLines(ls)
	add("json-lone-surrogate", "a lone surrogate escape: the line does not parse, FAIL", f)

	f = valid.clone()
	ls = lines(f["events.ndjson"])
	ls[len(ls)-1] = strings.Replace(ls[len(ls)-1], `"payload":{"n":40}`, "\"payload\":{\"n\":40,\"s\":\"\xff\"}", 1)
	f["events.ndjson"] = joinLines(ls)
	add("json-invalid-utf8", "an invalid UTF-8 byte inside a string: the line does not parse, FAIL", f)

	f = valid.clone()
	ls = lines(f["events.ndjson"])
	ls[len(ls)-1] = strings.Replace(ls[len(ls)-1], `"payload":{"n":40}`, `"payload":{"`+"\\"+`u0000n":40}`, 1)
	f["events.ndjson"] = joinLines(ls)
	add("json-nul-key", "an object key beginning with NUL: the line does not parse in object mode, FAIL", f)

	f = valid.clone()
	ls = lines(f["events.ndjson"])
	ls[len(ls)-1] = strings.Replace(ls[len(ls)-1], `"payload":{"n":40}`, `"payload":{"n":40.0}`, 1)
	f["events.ndjson"] = joinLines(ls)
	add("json-float-payload", "a float in a payload: the payload cannot be canonicalised, FAIL", f)

	f = valid.clone()
	ls = lines(f["events.ndjson"])
	ls[len(ls)-1] = strings.Replace(ls[len(ls)-1], `"payload":{"n":40}`, `"payload":{"n":9007199254740992}`, 1)
	f["events.ndjson"] = joinLines(ls)
	add("json-int-beyond-2p53", "an integer of 2^53 in a payload: outside the exactly representable range, FAIL", f)

	f = valid.clone()
	f["events.ndjson"] = bytes.Replace(f["events.ndjson"], []byte("\n"), []byte("\r\n"), -1)
	add("ndjson-crlf-blank-lines", "CRLF line endings and blank lines: PASS", func() files {
		f["events.ndjson"] = bytes.Replace(f["events.ndjson"], []byte("\r\n"), []byte("\r\n\r\n   \r\n"), 2)
		return f
	}())

	f = valid.clone()
	f["events.ndjson"] = bytes.Replace(f["events.ndjson"], []byte("\n"), []byte("\n\x0c\n"), 1)
	add("ndjson-form-feed-line", "a line holding only a form feed: not blank to PHP's trim, not valid JSON, FAIL", f)

	f = valid.clone()
	f["manifest.json"] = append(f["manifest.json"], []byte("\n{}")...)
	add("json-trailing-document", "a second document after manifest.json: not valid JSON, unknown format, ERROR", f)

	// --- zip archives ---
	tampered := bytes.Replace(valid["events.ndjson"], []byte(`"actor":"user:2"`), []byte(`"actor":"user:X"`), 1)
	base := ordered(valid)
	addEntries("zip-duplicate-entry-last-wins", "events.ndjson twice, the tampered copy last: the last entry is read, FAIL", append(base, entry{name: "events.ndjson", data: tampered}))
	addEntries("zip-duplicate-entry-first-tampered", "events.ndjson twice, the tampered copy first: the last entry is read, PASS", append([]entry{{name: "events.ndjson", data: tampered}}, base...))
	addEntries("zip-parent-path-shadows", "an entry named ../events.ndjson after the real one: it extracts as events.ndjson and shadows it, FAIL", append(base, entry{name: "../events.ndjson", data: tampered}))
	addEntries("zip-absolute-path-shadows", "an entry named /events.ndjson after the real one: it extracts as events.ndjson and shadows it, FAIL", append(base, entry{name: "/events.ndjson", data: tampered}))
	addEntries("zip-parent-path-only", "the only events.ndjson is stored as ../events.ndjson: it extracts as events.ndjson, PASS", append(without(base, "events.ndjson"), entry{name: "../events.ndjson", data: valid["events.ndjson"]}))
	addEntries("zip-directory-collision", "a directory entry named manifest.json/: the extraction fails, exit 1", append(base, entry{name: "manifest.json/", dir: true}))
	addEntries("zip-extra-entries", "entries the format does not name, including a backslash name: ignored, PASS", append(base, entry{name: "unrelated.txt", data: []byte("hello")}, entry{name: "deep/dir/file.bin", data: []byte{0}}, entry{name: `certificates\x.pdf`, data: []byte("%PDF")}))
	addEntries("zip-folder-wrapped", "every file under a top-level folder: manifest.json is missing, exit 1", prefixed(base, "bundle/"))

	// --- Ed25519 acceptance ---
	f = valid.clone()
	editJSON(f, "checkpoints.json", func(doc map[string]any) {
		cp := firstCheckpoint(doc)
		raw, _ := hex.DecodeString(cp["checkpoint_hash"].(string))
		cp["signature"] = hex.EncodeToString(smallOrderRSignature(raw))
	})
	add("ed25519-small-order-r", "a signature whose R is the identity point and which satisfies the equation under the real key: rejected as libsodium rejects it, FAIL", f)

	f = valid.clone()
	editJSON(f, "checkpoints.json", func(doc map[string]any) {
		cp := firstCheckpoint(doc)
		sig, _ := hex.DecodeString(cp["signature"].(string))
		cp["signature"] = hex.EncodeToString(nonCanonicalS(sig))
	})
	add("ed25519-non-canonical-s", "the genuine signature with S + l: rejected, FAIL", f)

	f = valid.clone()
	editJSON(f, "checkpoints.json", func(doc map[string]any) {
		cp := firstCheckpoint(doc)
		cp["public_key"] = "0100000000000000000000000000000000000000000000000000000000000000"
		cp["signature"] = "58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000"
	})
	editJSON(f, "manifest.json", func(doc map[string]any) {
		doc["signing_keys"] = append(doc["signing_keys"].([]any), map[string]any{"public_key": "0100000000000000000000000000000000000000000000000000000000000000", "created_at": "2026-01-02T03:04:05.000000Z", "retired_at": nil})
	})
	add("ed25519-small-order-public-key", "a checkpoint signed by the identity point with a signature every RFC 8032 verifier accepts: rejected, FAIL (and the key is untrusted)", f)

	// --- anchors ---
	f = anchored.clone()
	editJSON(f, "anchors.json", func(doc map[string]any) {
		a := doc["anchors"].([]any)[0].(map[string]any)
		tok := a["token"].(string)
		a["token"] = tok[:40] + flipBase64(tok[40]) + tok[41:]
	})
	add("anchor-token-byte-flipped", "one byte of the token changed: the token no longer matches token_hash, FAIL", f)

	f = anchored.clone()
	editJSON(f, "anchors.json", func(doc map[string]any) {
		a := doc["anchors"].([]any)[0].(map[string]any)
		a["checkpoint_hash"] = strings.Repeat("ab", 32)
	})
	add("anchor-unknown-checkpoint", "an anchor over a checkpoint hash the bundle does not carry, FAIL", f)

	add("anchor-bundle-roots-only", "the anchored corpus run without --tsa-roots: the built-in roots are the trusted set and the conformance TSA is not among them, so the chain does not reach a trusted root, FAIL (timestamps)", anchored.clone())

	// --- key windows ---
	add("key-window-retired", "the corpus key retired before the checkpoints were sealed (see keys-retired.json): FAIL (signing identity)", valid.clone())
	retired := map[string]any{"keys": []any{map[string]any{
		"key_id": "21fe31dfa154a261", "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		"algorithm": "ed25519", "created_at": "2025-01-01T00:00:00.000000Z", "retired_at": "2026-01-01T00:00:00.000000Z",
	}}}
	os.WriteFile(filepath.Join(*out, "keys-retired.json"), marshalPretty(retired), 0o644)

	// --- redactions ---
	f = redacted.clone()
	delete(f, "declarations.ndjson")
	add("redaction-declarations-missing", "the redacted corpus without declarations.ndjson: FAIL (redactions)", f)

	f = redacted.clone()
	f["declarations.ndjson"] = bytes.Replace(f["declarations.ndjson"], []byte(`"runs":[[20,20]]`), []byte(`"runs":[[21,21]]`), 1)
	add("redaction-declaration-names-other-event", "the declaration's targets no longer name the absent event (its hashes break too): FAIL", f)

	// --- write everything ---
	var readme strings.Builder
	readme.WriteString("# Hostile fixtures\n\nGenerated by `go run ./tools/hostile` from the conformance corpus; do not edit by hand. Each fixture pins one rule of FORMAT.md or one input that stopped verify.php 1.5.0 before a verdict. Expectations live in `corpus/expected.json`.\n\n| Fixture | Pins |\n| --- | --- |\n")
	for _, fx := range fixtures {
		writeZip(filepath.Join(*out, fx.name+".zip"), fx.entries)
		fmt.Fprintf(&readme, "| `%s` | %s |\n", fx.name, fx.doc)
	}
	os.WriteFile(filepath.Join(*out, "README.md"), []byte(readme.String()), 0o644)
	fmt.Printf("wrote %d fixtures to %s\n", len(fixtures), *out)
}

func without(entries []entry, name string) []entry {
	var out []entry
	for _, e := range entries {
		if e.name != name {
			out = append(out, e)
		}
	}
	return out
}

func prefixed(entries []entry, prefix string) []entry {
	var out []entry
	for _, e := range entries {
		out = append(out, entry{name: prefix + e.name, data: e.data, dir: e.dir})
	}
	return out
}

// flipBase64 returns a different base64 alphabet character.
func flipBase64(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}
