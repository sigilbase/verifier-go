package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/sigilbase/verifier-go/internal/bundle"
	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/internal/edsig"
	"github.com/sigilbase/verifier-go/internal/merkle"
)

// knownFormats lists the format ids this verifier understands, in the
// order verify.php names them in its error message.
var knownFormats = []string{
	"sigilbase-evidence/1",
	"sigilbase-evidence/1.1",
	"sigilbase-evidence/1.2",
	"sigilbase-evidence/1.3",
	"sigilbase-evidence/1.4",
	"sigilbase-evidence/1.5",
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// bundleResult is what verify_bundle returns.
type bundleResult struct {
	streamID        string
	rangeFrom       int64
	rangeTo         int64
	eventCount      int64
	checkpointCount int64
	redactedCount   int64
	// cumulativeRoots holds the cumulative RFC 6962 root at the tree sizes
	// something asked about, hex, as verify.php captures them while the
	// events stream past.
	cumulativeRoots map[int64]string
	// proofNodes is the streamed consistency proof when walkOptions asked
	// for one and the walk could build it.
	proofNodes [][]byte
	proofBuilt bool
}

// walkOptions are the extra requests the consistency modes make of a walk.
type walkOptions struct {
	// wantedRootSizes are extra cumulative tree sizes to capture.
	wantedRootSizes []int64
	// proofFrom, when positive, asks for the RFC 6962 consistency proof from
	// that tree size to the bundle's range_to, built as the leaves stream
	// past rather than from an array of them.
	proofFrom int64
}

// counter is a sequence expectation that may have overflowed: PHP turns
// PHP_INT_MAX + 1 into a float, which then equals no integer.
type counter struct {
	value      int64
	overflowed bool
}

func (c counter) next(v int64) counter {
	if v == math.MaxInt64 {
		return counter{overflowed: true}
	}
	return counter{value: v + 1}
}

func (c counter) equals(v int64) bool { return !c.overflowed && c.value == v }

func (c counter) minusOneEquals(v int64) bool { return !c.overflowed && c.value-1 == v }

func (c counter) String() string {
	if c.overflowed {
		return "9.2233720368548E+18"
	}
	return fmt.Sprint(c.value)
}

func (c counter) minusOneString() string {
	if c.overflowed {
		return "9.2233720368548E+18"
	}
	return fmt.Sprint(c.value - 1)
}

// readRequired is read_bundle_file: a missing required file stops the run
// with exit 1, because missing pieces are indistinguishable from deletion.
func readRequired(b bundle.Reader, name string) ([]byte, *hardError) {
	if !b.IsFile(name) {
		return nil, hard(fmt.Sprintf("bundle is missing [%s]", name), 1)
	}
	data, err := b.ReadWhole(name)
	if err != nil {
		return nil, err.(*hardError)
	}
	return data, nil
}

// decodeOptional is json_decode((string) file_get_contents($path), false)
// for a file that may be absent or malformed: the result is nil where PHP
// gets null.
func decodeOptional(b bundle.Reader, name string) (*cjson.Value, *hardError) {
	if !b.IsFile(name) {
		return nil, nil
	}
	data, err := b.ReadWhole(name)
	if err != nil {
		return nil, err.(*hardError)
	}
	v, perr := cjson.Parse(data)
	if perr != nil {
		return nil, nil
	}
	return v, nil
}

func decode(data []byte) *cjson.Value {
	v, err := cjson.Parse(data)
	if err != nil {
		return nil
	}
	return v
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// entryPreimage is the v1 entry hash preimage over an event's own fields
// (FORMAT.md, "Entry hash"), with absent fields as null exactly as
// verify.php builds it.
func entryPreimage(streamID *cjson.Value, seq *cjson.Value, ev *cjson.Value) *cjson.Value {
	obj := cjson.NewObject()
	obj.Set("v", &cjson.Value{Kind: cjson.Int, Int: 1})
	obj.Set("stream", streamID)
	obj.Set("seq", seq)
	for _, k := range []string{"occurred_at", "received_at", "actor", "action", "resource", "payload_hash"} {
		obj.Set(k, fieldOrNull(ev, k))
	}
	obj.Set("prev", fieldOrNull(ev, "prev_hash"))
	return &cjson.Value{Kind: cjson.Object, Obj: obj}
}

func fieldOrNull(v *cjson.Value, key string) *cjson.Value {
	f := v.Field(key)
	if f == nil {
		return &cjson.Value{Kind: cjson.Null}
	}
	return f
}

func stringValue(s string) *cjson.Value { return &cjson.Value{Kind: cjson.String, Str: s} }
func intValue(n int64) *cjson.Value     { return &cjson.Value{Kind: cjson.Int, Int: n} }

// checkpointPreimage is the v1 checkpoint hash preimage (FORMAT.md,
// "Checkpoint hash"). v is the literal 1 for checkpoints.json and the
// checkpoint's own v field for a declaration proof's checkpoint, exactly
// as verify.php builds each.
func checkpointPreimage(v *cjson.Value, stream *cjson.Value, from, to, root, prev, createdAt *cjson.Value) *cjson.Value {
	obj := cjson.NewObject()
	obj.Set("v", v)
	obj.Set("stream", stream)
	obj.Set("from", from)
	obj.Set("to", to)
	obj.Set("root", root)
	obj.Set("prev_checkpoint", prev)
	obj.Set("created_at", createdAt)
	return &cjson.Value{Kind: cjson.Object, Obj: obj}
}

// verifyBundle is verify.php's verify_bundle. Progress goes to the log;
// failures land in the run and demote the results.
func (r *run) verifyBundle(target string, skipAnchors bool, wopts *walkOptions, _ any) (*bundleResult, *hardError) {
	if wopts == nil {
		wopts = &walkOptions{}
	}
	b, herr := bundle.Open(target)
	if herr != nil {
		return nil, herr
	}
	defer b.Close()

	// ---- manifest.json ------------------------------------------------------

	manifestBytes, herr := readRequired(b, "manifest.json")
	if herr != nil {
		return nil, herr
	}
	manifest := decode(manifestBytes)

	var format string
	if isObject(manifest) && isString(manifest.Field("format")) {
		f := manifest.Field("format").Str
		for _, k := range knownFormats {
			if f == k {
				format = f
			}
		}
	}
	if format == "" {
		return nil, hard("manifest.json is missing or has an unknown format (expected one of: "+strings.Join(knownFormats, ", ")+")", ExitError)
	}

	var streamID *cjson.Value
	var rangeFromV, rangeToV *cjson.Value
	if isObject(manifest) {
		if s := manifest.Field("stream"); isObject(s) {
			streamID = s.Field("id")
		}
		if rg := manifest.Field("range"); isObject(rg) {
			rangeFromV = rg.Field("from")
			rangeToV = rg.Field("to")
		}
	}
	if !isString(streamID) || !isInt(rangeFromV) || !isInt(rangeToV) {
		return nil, hard("manifest.json is missing stream id or range", 1)
	}
	stream := streamID.Str
	rangeFrom := rangeFromV.Int
	rangeTo := rangeToV.Int

	// Each trusted key carries its active window as the manifest states
	// it; a later entry for the same key replaces an earlier one.
	type manifestKey struct{ createdAt, retiredAt *cjson.Value }
	manifestKeys := map[string]manifestKey{}
	for _, key := range iterValues(manifest.Field("signing_keys")) {
		if pk := key.Field("public_key"); isString(pk) {
			manifestKeys[lower(pk.Str)] = manifestKey{createdAt: key.Field("created_at"), retiredAt: key.Field("retired_at")}
		}
	}
	if len(manifestKeys) == 0 {
		return nil, hard("manifest.json lists no signing keys", 1)
	}

	r.info(fmt.Sprintf("Stream: %s", stream))
	r.info(fmt.Sprintf("Range:  %d..%d", rangeFrom, rangeTo))
	r.info(fmt.Sprintf("Keys:   %d trusted signing key(s) in manifest", len(manifestKeys)))

	// ---- redactions.json (1.2, optional) -------------------------------------

	redactionsBySequence := map[int64]*cjson.Value{}
	if b.IsFile("redactions.json") {
		doc, herr := decodeOptional(b, "redactions.json")
		if herr != nil {
			return nil, herr
		}
		var records *cjson.Value
		if isObject(doc) {
			records = doc.Field("redactions")
		}
		if !isArray(records) {
			r.report(`redactions.json is present but malformed - expected a "redactions" list`, ResultContent)
		} else {
			for _, record := range records.Arr {
				var declared *cjson.Value
				if isObject(record) {
					declared = record.Field("sequence")
				}
				if !isInt(declared) {
					r.report("redactions.json contains an entry without an integer sequence", ResultContent)
					continue
				}
				if declared.Int < rangeFrom || declared.Int > rangeTo {
					r.note(fmt.Sprintf("redactions.json declares sequence %d, outside this bundle's range", declared.Int))
					continue
				}
				redactionsBySequence[declared.Int] = record
			}
		}
	}

	// ---- checkpoints.json, read early --------------------------------------

	checkpointBytes, herr := readRequired(b, "checkpoints.json")
	if herr != nil {
		return nil, herr
	}
	checkpointDoc := decode(checkpointBytes)
	var checkpoints *cjson.Value
	if isObject(checkpointDoc) {
		checkpoints = checkpointDoc.Field("checkpoints")
	}
	if !isArray(checkpoints) || len(checkpoints.Arr) == 0 {
		return nil, hard("checkpoints.json contains no checkpoints", 1)
	}

	type cpRange struct{ from, to int64 }
	var checkpointRanges []cpRange
	for _, cp := range checkpoints.Arr {
		if isInt(cp.Field("from")) && isInt(cp.Field("to")) {
			checkpointRanges = append(checkpointRanges, cpRange{cp.Field("from").Int, cp.Field("to").Int})
		}
	}

	retainSequences, herr := r.declarationSequencesInRange(b, stream, rangeFrom, rangeTo)
	if herr != nil {
		return nil, herr
	}

	rootSizes := map[int64]bool{rangeTo: true}
	for _, rg := range checkpointRanges {
		rootSizes[rg.to] = true
	}
	for _, size := range wopts.wantedRootSizes {
		rootSizes[size] = true
	}
	if wopts.proofFrom > 0 {
		rootSizes[wopts.proofFrom] = true
	}
	sizes, herr := consistencyTreeSizes(b)
	if herr != nil {
		return nil, herr
	}
	for _, size := range sizes {
		rootSizes[size] = true
	}

	// ---- events.ndjson -----------------------------------------------------

	r.info("Checking events.ndjson (hash chain)...")

	if !b.IsFile("events.ndjson") {
		return nil, hard("bundle is missing [events.ndjson]", 1)
	}
	eventsFile, err := b.Open("events.ndjson")
	if err != nil {
		return nil, err.(*hardError)
	}
	defer eventsFile.Close()

	var eventCount int64
	expected := counter{value: rangeFrom}
	// A range starting at sequence 1 must chain from the 32-zero-byte hash;
	// ranges starting later trust the first event's prev and verify onwards.
	var prevHash *cjson.Value
	if rangeFrom == 1 {
		prevHash = stringValue(zeroHash)
	}
	entryHashBySequence := map[int64]string{}
	var redactedCount int64
	absentSequences := map[int64]bool{}
	var absentOrder []int64
	absenceKinds := map[int64]string{}

	var cumulativeStack, checkpointStack merkle.Stack
	cumulativeRootAt := map[int64]string{}
	rebuiltRootFor := map[int64]string{}
	checkpointLeavesFor := map[int64]int64{}
	var checkpointLeafCount int64
	checkpointIndex := 0

	var collector *merkle.Collector
	if wopts.proofFrom > 0 && rangeFrom == 1 && wopts.proofFrom <= rangeTo {
		if c, err := merkle.NewCollector(int(wopts.proofFrom), int(rangeTo)); err == nil {
			collector = c
		}
	}

	closeCheckpoint := func() {
		closingFrom := checkpointRanges[checkpointIndex].from
		if root, ok := checkpointStack.Root(); ok {
			rebuiltRootFor[closingFrom] = hex.EncodeToString(root)
		} else {
			rebuiltRootFor[closingFrom] = ""
		}
		checkpointLeavesFor[closingFrom] = checkpointLeafCount
		checkpointStack.Reset()
		checkpointLeafCount = 0
		checkpointIndex++
	}

	lines := bundle.NewLines(eventsFile)
	for lines.Next() {
		line := lines.Line()
		if bundle.IsBlank(line) {
			continue
		}
		event, perr := cjson.Parse(line)
		if perr != nil || !isObject(event) {
			r.report(fmt.Sprintf("events.ndjson line %d is not valid JSON", lines.Number()+1), ResultContent)
			continue
		}

		eventCount++
		seqV := event.Field("seq")
		if !isInt(seqV) {
			r.report("an event is missing its sequence number", ResultContent)
			continue
		}
		sequence := seqV.Int

		if !expected.equals(sequence) {
			r.report(fmt.Sprintf("sequence %d: expected sequence %s here - an event was deleted, inserted, or reordered", sequence, expected), ResultContent)
		}

		// Payload hash: recomputed from the payload itself, except for a
		// redacted event, whose content no longer exists. An absent payload
		// is accepted only when every signal agrees (FORMAT.md, "Redacted
		// event"), and from 1.5 only against an authenticated declaration,
		// checked once the checkpoints are verified.
		payloadState := event.Field("payload_state")
		if nullish(payloadState) {
			payloadState = stringValue("present")
		}
		payloadPresent := !nullish(event.Field("payload"))
		declaration := redactionsBySequence[sequence]

		if !strEq(payloadState, "present") && !strEq(payloadState, "redacted") {
			r.report(fmt.Sprintf("sequence %d: unknown payload_state %s", sequence, jsonForMessage(payloadState)), ResultContent)
		} else if strEq(payloadState, "redacted") || !payloadPresent {
			if payloadPresent {
				r.report(fmt.Sprintf("sequence %d: payload_state says redacted but a payload is present - the bundle contradicts itself", sequence), ResultContent)
			} else if !strEq(payloadState, "redacted") {
				r.report(fmt.Sprintf(`sequence %d: payload is absent but not marked payload_state "redacted" - absence must be declared, never implied`, sequence), ResultContent)
			} else {
				if !absentSequences[sequence] {
					absentOrder = append(absentOrder, sequence)
				}
				absentSequences[sequence] = true
				redactedCount++
				// Which ceremony destroyed it. Unknown values read as a
				// redaction, the stricter of the two to satisfy.
				kind := "redacted"
				if strEq(event.Field("absence"), "erased") {
					kind = "erased"
				}
				absenceKinds[sequence] = kind
				redactedAt := "an undeclared date"
				if declaration != nil && isString(declaration.Field("redacted_at")) {
					redactedAt = phpSubstr(declaration.Field("redacted_at").Str, 10)
				}
				r.note(fmt.Sprintf("sequence %d: payload redacted %s, hashes preserved, chain verified from the recorded payload_hash", sequence, redactedAt))
			}
		} else {
			if declaration != nil {
				r.report(fmt.Sprintf("sequence %d: redactions.json declares this payload redacted but it is present - the bundle contradicts itself", sequence), ResultContent)
			}
			canon, cerr := cjson.Canonical(fieldOrNull(event, "payload"))
			if cerr != nil {
				r.report(fmt.Sprintf("sequence %d: payload cannot be canonicalised (%s)", sequence, cerr.Error()), ResultContent)
			} else if lower(text(event.Field("payload_hash"))) != sha256Hex(canon) {
				r.report(fmt.Sprintf("sequence %d: payload_hash does not match the payload content - the payload was modified", sequence), ResultContent)
			}
		}

		// Chain link: each event must reference the previous entry hash.
		if prevHash != nil && !strictEqual(event.Field("prev_hash"), prevHash) {
			r.report(fmt.Sprintf("sequence %d: prev_hash does not match the previous entry hash - the chain is broken here", sequence), ResultContent)
		}

		// Entry hash: recompute the v1 preimage from the event's own fields.
		preimage, cerr := cjson.Canonical(entryPreimage(stringValue(stream), seqV, event))
		if cerr != nil {
			r.report(fmt.Sprintf("sequence %d: the event's fields cannot be canonicalised (%s) - the entry hash cannot be recomputed", sequence, cerr.Error()), ResultContent)
		} else if lower(text(event.Field("entry_hash"))) != sha256Hex(preimage) {
			r.report(fmt.Sprintf("sequence %d: entry_hash does not recompute from the stored fields - a field was modified", sequence), ResultContent)
		}

		entryHash := lower(text(event.Field("entry_hash")))
		if retainSequences[sequence] {
			entryHashBySequence[sequence] = entryHash
		}

		// Close every checkpoint this sequence has passed before the event
		// is counted into one: a deleted event means the boundary never
		// arrives, and a tree left open would fold the next checkpoint's
		// events into this one's root.
		for checkpointIndex < len(checkpointRanges) && sequence > checkpointRanges[checkpointIndex].to {
			closeCheckpoint()
		}

		if raw, ok := hexBytes(entryHash); ok && len(raw) == 32 {
			cumulativeStack.Append(raw)
			checkpointStack.Append(raw)
			checkpointLeafCount++
			if collector != nil {
				collector.Append(raw)
			}
		}

		if root, ok := cumulativeStack.Root(); rangeFrom == 1 && ok && rootSizes[sequence] {
			cumulativeRootAt[sequence] = hex.EncodeToString(root)
		}

		prevHash = event.Field("prev_hash")
		if eh := event.Field("entry_hash"); nullish(eh) {
			prevHash = nil
		} else {
			prevHash = eh
		}
		expected = expected.next(sequence)
	}
	if lerr := lines.Err(); lerr != nil {
		if lerr == bundle.ErrLineTooLong {
			return nil, hard(fmt.Sprintf("events.ndjson line %d is longer than the %d bytes this verifier accepts; nothing was verified", lines.Number()+2, bundle.MaxLineBytes), ExitError)
		}
		return nil, hard("could not read [events.ndjson]", 1)
	}

	for checkpointIndex < len(checkpointRanges) {
		closeCheckpoint()
	}

	if !expected.minusOneEquals(rangeTo) {
		r.report(fmt.Sprintf("events end at sequence %s but the manifest declares %d - trailing events are missing", expected.minusOneString(), rangeTo), ResultContent)
	}

	if eventCount == 0 {
		return nil, hard("events.ndjson contains no events", 1)
	}

	// ---- checkpoints.json --------------------------------------------------

	r.info("Checking checkpoints.json (signed Merkle checkpoints)...")

	var prevCheckpointHash *cjson.Value
	if rangeFrom == 1 {
		prevCheckpointHash = stringValue(zeroHash)
	}
	expectedFrom := counter{value: rangeFrom}
	checkpointHashes := map[string]bool{}

	for _, cp := range checkpoints.Arr {
		fromV, toV := cp.Field("from"), cp.Field("to")
		if !isInt(fromV) || !isInt(toV) {
			r.report("a checkpoint is missing its range", ResultContent)
			continue
		}
		from, to := fromV.Int, toV.Int
		label := fmt.Sprintf("checkpoint %d..%d", from, to)

		if !expectedFrom.equals(from) {
			r.report(fmt.Sprintf("%s: expected the range to start at %s - a checkpoint is missing or reordered", label, expectedFrom), ResultContent)
		}

		declaredHash := lower(text(cp.Field("checkpoint_hash")))
		preimage, cerr := cjson.Canonical(checkpointPreimage(intValue(1), stringValue(stream), fromV, toV, fieldOrNull(cp, "root"), fieldOrNull(cp, "prev_checkpoint"), fieldOrNull(cp, "created_at")))
		if cerr != nil {
			r.report(fmt.Sprintf("%s: the checkpoint's fields cannot be canonicalised (%s) - the checkpoint hash cannot be recomputed", label, cerr.Error()), ResultContent)
		} else if declaredHash != sha256Hex(preimage) {
			r.report(fmt.Sprintf("%s: checkpoint_hash does not recompute from its fields - the checkpoint was modified", label), ResultContent)
		}

		if prevCheckpointHash != nil && !strictEqual(cp.Field("prev_checkpoint"), prevCheckpointHash) {
			r.report(fmt.Sprintf("%s: prev_checkpoint does not match the previous checkpoint hash - a checkpoint was removed or replaced", label), ResultContent)
		}

		publicKeyHex := lower(text(cp.Field("public_key")))
		manifestKey, inManifest := manifestKeys[publicKeyHex]
		if !inManifest {
			r.report(fmt.Sprintf("%s: signed by a key that is not in the manifest's signing keys", label), ResultContent)
		}

		// Signing identity: the signature proves that a key signed this;
		// only the trusted set can say whose.
		fingerprint := keyFingerprint(publicKeyHex)
		trusted := r.trusted.lookup(publicKeyHex)
		createdAtText := text(cp.Field("created_at"))
		if trusted == nil {
			r.keys.set(fingerprint, "bundle only")
			r.unconfirmed(fmt.Sprintf("%s: signed by key %s, which is not in the %s - the bundle is internally consistent, but nothing here establishes that Sigilbase produced it", label, fingerprint, r.trustedSetSource), ResultIdentity)
			// Fall back to the window the manifest states: it is the only
			// window information available, and a bundle that contradicts
			// itself is still worth catching.
			if inManifest {
				for _, problem := range windowProblems(manifestKey.createdAt, manifestKey.retiredAt, createdAtText) {
					r.report(fmt.Sprintf("%s: %s", label, problem), ResultContent)
				}
			}
		} else {
			r.keys.set(fingerprint, r.trustedSetSource)
			// The trusted set's window wins outright: a bundle that could
			// widen its key's window could seal anything at any time.
			c, ret := trusted.window()
			for _, problem := range windowProblems(c, ret, createdAtText) {
				r.report(fmt.Sprintf("%s: %s", label, problem), ResultIdentity)
			}
		}

		signature, sigOK := hexBytes(text(cp.Field("signature")))
		message, msgOK := hexBytes(declaredHash)
		publicKey, pkOK := hexBytes(publicKeyHex)
		signatureValid := sigOK && msgOK && pkOK &&
			len(signature) == 64 && len(publicKey) == 32 && len(message) != 0 &&
			edsig.Verify(publicKey, message, signature)
		if !signatureValid {
			r.report(fmt.Sprintf("%s: the Ed25519 signature does not verify - the signature is forged or the checkpoint was modified", label), ResultContent)
		}

		// Merkle root: rebuilt as the events streamed past, keyed by the
		// checkpoint's first sequence. A short leaf count names the first
		// sequence that never arrived.
		rebuiltRoot := rebuiltRootFor[from]
		received := checkpointLeavesFor[from]
		if received < to-from+1 {
			r.report(fmt.Sprintf("%s: event %d is missing from events.ndjson", label, from+received), ResultContent)
		} else if lower(text(cp.Field("root"))) != rebuiltRoot {
			r.report(fmt.Sprintf("%s: the Merkle root does not recompute from the events it covers", label), ResultContent)
		}

		checkpointHashes[declaredHash] = true
		if ch := cp.Field("checkpoint_hash"); nullish(ch) {
			prevCheckpointHash = nil
		} else {
			prevCheckpointHash = ch
		}
		expectedFrom = expectedFrom.next(to)
	}

	if !expectedFrom.minusOneEquals(rangeTo) {
		r.report(fmt.Sprintf("checkpoints cover up to sequence %s but the manifest declares %d", expectedFrom.minusOneString(), rangeTo), ResultScope)
	}

	// ---- declarations.ndjson / declaration_proofs.json (1.5) ----------------

	if len(absentSequences) > 0 {
		if herr := r.checkDeclarations(b, format, stream, rangeFrom, rangeTo, absentOrder, entryHashBySequence, absenceKinds); herr != nil {
			return nil, herr
		}
	} else {
		r.info("No payload in this bundle is absent; nothing to declare.")
	}

	// ---- anchors.json (format 1.1, optional) --------------------------------

	if herr := r.checkAnchors(b, skipAnchors, checkpointHashes); herr != nil {
		return nil, herr
	}

	// ---- certificates/ (format 1.3, optional, informational) -----------------

	if herr := r.checkCertificates(b, manifest); herr != nil {
		return nil, herr
	}

	// ---- documents.json / signatures.json / links.json (format 1.4) ----------

	if herr := r.checkSigilSign(b); herr != nil {
		return nil, herr
	}

	// ---- consistency.json (format 1.1, optional) -----------------------------

	if herr := r.checkConsistencyFile(b, rangeFrom, rangeTo, cumulativeRootAt); herr != nil {
		return nil, herr
	}

	result := &bundleResult{
		streamID:        stream,
		rangeFrom:       rangeFrom,
		rangeTo:         rangeTo,
		eventCount:      eventCount,
		checkpointCount: int64(len(checkpoints.Arr)),
		redactedCount:   redactedCount,
		cumulativeRoots: cumulativeRootAt,
	}
	if collector != nil {
		if nodes, err := collector.Nodes(); err == nil {
			result.proofNodes = nodes
			result.proofBuilt = true
		}
	}
	return result, nil
}

// phpSubstr is substr($s, 0, n) on bytes.
func phpSubstr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// declarationSequencesInRange mirrors declaration_sequences_in_range: the
// sequences declarations occupy inside this bundle's own range, read
// before the events are walked so the walk knows which entry hashes to
// keep.
func (r *run) declarationSequencesInRange(b bundle.Reader, stream string, rangeFrom, rangeTo int64) (map[int64]bool, *hardError) {
	sequences := map[int64]bool{}
	if !b.IsFile("declarations.ndjson") {
		return sequences, nil
	}
	f, err := b.Open("declarations.ndjson")
	if err != nil {
		return nil, err.(*hardError)
	}
	defer f.Close()
	lines := bundle.NewLines(f)
	for lines.Next() {
		line := lines.Line()
		if bundle.IsBlank(line) {
			continue
		}
		record, perr := cjson.Parse(line)
		if perr != nil || !isObject(record) || !strEq(record.Field("stream"), stream) {
			continue
		}
		if seq := record.Field("seq"); isInt(seq) && seq.Int >= rangeFrom && seq.Int <= rangeTo {
			sequences[seq.Int] = true
		}
	}
	if lerr := lines.Err(); lerr != nil {
		if lerr == bundle.ErrLineTooLong {
			return nil, hard(fmt.Sprintf("declarations.ndjson line %d is longer than the %d bytes this verifier accepts; nothing was verified", lines.Number()+2, bundle.MaxLineBytes), ExitError)
		}
		return nil, hard("could not read [declarations.ndjson]", 1)
	}
	return sequences, nil
}

// consistencyTreeSizes mirrors consistency_tree_sizes: every cumulative
// tree size consistency.json refers to.
func consistencyTreeSizes(b bundle.Reader) ([]int64, *hardError) {
	doc, herr := decodeOptional(b, "consistency.json")
	if herr != nil {
		return nil, herr
	}
	if !isObject(doc) {
		return nil, nil
	}
	var sizes []int64
	for _, state := range iterValues(doc.Field("checkpoint_states")) {
		if ts := state.Field("tree_size"); isInt(ts) {
			sizes = append(sizes, ts.Int)
		}
	}
	if proof := doc.Field("proof"); isObject(proof) {
		for _, field := range []string{"from_tree_size", "to_tree_size"} {
			if v := proof.Field(field); isInt(v) {
				sizes = append(sizes, v.Int)
			}
		}
	}
	return sizes, nil
}
