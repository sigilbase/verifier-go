package verify

import (
	"encoding/hex"
	"fmt"

	"github.com/sigilbase/verifier-go/internal/bundle"
	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/internal/edsig"
	"github.com/sigilbase/verifier-go/internal/merkle"
)

// declarationCovers mirrors declaration_covers: does a declaration's
// targets block name this event? Targets are runs, [[2,5],[9,9]], and a
// run is never expanded.
func declarationCovers(payload *cjson.Value, stream string, sequence int64) bool {
	if !isObject(payload) {
		return false
	}
	targets := payload.Field("targets")
	if !isArray(targets) {
		return false
	}
	for _, target := range targets.Arr {
		if !isObject(target) || !strEq(target.Field("stream"), stream) || !isArray(target.Field("runs")) {
			continue
		}
		for _, run := range target.Field("runs").Arr {
			if !isArray(run) || len(run.Arr) != 2 || !isInt(run.Arr[0]) || !isInt(run.Arr[1]) {
				continue
			}
			if sequence >= run.Arr[0].Int && sequence <= run.Arr[1].Int {
				return true
			}
		}
	}
	return false
}

// declarationSelfProblems mirrors declaration_self_problems: a
// declaration's payload against its payload_hash, and its entry hash
// against all of its fields, including the stream the declaration itself
// belongs to.
func declarationSelfProblems(record *cjson.Value) []string {
	var problems []string
	label := "sequence " + textOr(record.Field("seq"), "?")

	canon, err := cjson.Canonical(fieldOrNull(record, "payload"))
	if err != nil {
		problems = append(problems, fmt.Sprintf("%s: payload cannot be canonicalised (%s)", label, err.Error()))
	} else if lower(text(record.Field("payload_hash"))) != sha256Hex(canon) {
		problems = append(problems, fmt.Sprintf("%s: payload_hash does not match the declaration's own payload", label))
	}

	preimage, err := cjson.Canonical(entryPreimage(fieldOrNull(record, "stream"), fieldOrNull(record, "seq"), record))
	if err != nil {
		problems = append(problems, fmt.Sprintf("%s: the declaration's fields cannot be canonicalised (%s) - its entry hash cannot be recomputed", label, err.Error()))
	} else if lower(text(record.Field("entry_hash"))) != sha256Hex(preimage) {
		problems = append(problems, fmt.Sprintf("%s: entry_hash does not recompute from the declaration's own fields", label))
	}
	return problems
}

// authenticated is verify.php's $authenticated array: entry hash to
// declaration, in insertion order, with removals.
type authenticatedSet struct {
	order   []string
	records map[string]*cjson.Value
}

func (a *authenticatedSet) add(hash string, record *cjson.Value) {
	if a.records == nil {
		a.records = map[string]*cjson.Value{}
	}
	if _, seen := a.records[hash]; !seen {
		a.order = append(a.order, hash)
	}
	a.records[hash] = record
}

func (a *authenticatedSet) remove(hash string) { delete(a.records, hash) }

func (a *authenticatedSet) get(hash string) *cjson.Value { return a.records[hash] }

// each visits the live entries in insertion order.
func (a *authenticatedSet) each(fn func(hash string, record *cjson.Value) bool) {
	for _, h := range a.order {
		record, ok := a.records[h]
		if !ok {
			continue
		}
		if !fn(h, record) {
			return
		}
	}
}

// checkDeclarations is verify.php's check_declarations: the redaction
// rule of format 1.5. An absent payload is accepted only against a
// declaration the verifier can authenticate and that names this very
// event. Every condition must hold, or the absence fails.
func (r *run) checkDeclarations(b bundle.Reader, format, stream string, rangeFrom, rangeTo int64, absent []int64, entryHashBySequence map[int64]string, absenceKinds map[int64]string) *hardError {
	count := len(absent)
	r.info(fmt.Sprintf("Checking declarations for %d absent payload(s)...", count))

	if format != "sigilbase-evidence/1.5" {
		r.report(fmt.Sprintf("this bundle is %s and carries %d absent payload(s). Formats before sigilbase-evidence/1.5 do not carry the declarations that destroyed them, so the absences cannot be verified. Export the range again from Sigilbase to get a bundle that can be.", format, count), ResultRedactions)
		return nil
	}

	if !b.IsFile("declarations.ndjson") {
		r.report("declarations.ndjson is missing, but payloads in this bundle are absent - evidence with pieces deleted must never pass", ResultRedactions)
		return nil
	}

	var authenticated authenticatedSet
	f, err := b.Open("declarations.ndjson")
	if err != nil {
		return err.(*hardError)
	}
	lines := bundle.NewLines(f)
	for lines.Next() {
		line := lines.Line()
		if bundle.IsBlank(line) {
			continue
		}
		record, perr := cjson.Parse(line)
		if perr != nil || !isObject(record) {
			r.report(fmt.Sprintf("declarations.ndjson line %d is not valid JSON", lines.Number()+1), ResultRedactions)
			continue
		}
		problems := declarationSelfProblems(record)
		for _, p := range problems {
			r.report("declaration "+p, ResultRedactions)
		}
		if len(problems) == 0 {
			authenticated.add(lower(text(record.Field("entry_hash"))), record)
		}
	}
	f.Close()
	if lerr := lines.Err(); lerr != nil {
		if lerr == bundle.ErrLineTooLong {
			return hard(fmt.Sprintf("declarations.ndjson line %d is longer than the %d bytes this verifier accepts; nothing was verified", lines.Number()+2, bundle.MaxLineBytes), ExitError)
		}
		return hard("could not read [declarations.ndjson]", 1)
	}

	// Sealing: inside the exported range by the checkpoints already
	// rebuilt, its entry hash being the one the chain walked; outside it,
	// by an audit path to its checkpoint.
	proofs, herr := loadDeclarationProofs(b)
	if herr != nil {
		return herr
	}
	for _, entryHash := range append([]string(nil), authenticated.order...) {
		record := authenticated.get(entryHash)
		if record == nil {
			continue
		}
		inThisStream := strEq(record.Field("stream"), stream)
		seq := record.Field("seq")
		if inThisStream && isInt(seq) && seq.Int >= rangeFrom && seq.Int <= rangeTo {
			if walked, ok := entryHashBySequence[seq.Int]; !ok || walked != entryHash {
				r.report(fmt.Sprintf("declaration at sequence %d: its entry hash is not the one events.ndjson carries at that sequence - the bundle contradicts itself", seq.Int), ResultRedactions)
				authenticated.remove(entryHash)
			}
			continue
		}
		if problem := r.declarationProofProblem(proofs, entryHash, record); problem != "" {
			r.report(problem, ResultRedactions)
			authenticated.remove(entryHash)
		}
	}

	// Now the rule itself, event by event.
	for _, sequence := range absent {
		wanted := "payload.redacted"
		if absenceKinds[sequence] == "erased" {
			wanted = "pii.subject_erased"
		}
		matched := false
		authenticated.each(func(_ string, record *cjson.Value) bool {
			if !declarationCovers(record.Field("payload"), stream, sequence) {
				return true
			}
			action := record.Field("action")
			// A supplement counts only beside its authenticated original.
			if strEq(action, "declaration.supplemented") {
				var original *cjson.Value
				if p := record.Field("payload"); isObject(p) {
					if d := p.Field("declaration"); isObject(d) {
						original = d.Field("entry_hash")
					}
				}
				var originalRecord *cjson.Value
				if isString(original) {
					originalRecord = authenticated.get(lower(original.Str))
				}
				if originalRecord == nil {
					r.report(fmt.Sprintf("sequence %d: a supplementary declaration names this event, but the original declaration it supplements is not in the bundle - a supplement proves nothing alone", sequence), ResultRedactions)
					return true
				}
				action = originalRecord.Field("action")
			}
			if !strEq(action, wanted) {
				return true
			}
			// Same stream: a declaration cannot precede the event it destroyed.
			if strEq(record.Field("stream"), stream) && isInt(record.Field("seq")) && record.Field("seq").Int <= sequence {
				r.report(fmt.Sprintf("sequence %d: the declaration naming it sits at sequence %d, at or before the event itself - a payload cannot be declared destroyed before it existed", sequence, record.Field("seq").Int), ResultRedactions)
				return true
			}
			matched = true
			return false
		})
		if !matched {
			r.report(fmt.Sprintf("sequence %d: the payload is absent and no authenticated %s declaration in this bundle names it - absence must be declared, never implied", sequence, wanted), ResultRedactions)
		}
	}
	return nil
}

// loadDeclarationProofs mirrors load_declaration_proofs:
// declaration_proofs.json indexed by the declaration entry hash it proves.
func loadDeclarationProofs(b bundle.Reader) (map[string]*cjson.Value, *hardError) {
	indexed := map[string]*cjson.Value{}
	doc, herr := decodeOptional(b, "declaration_proofs.json")
	if herr != nil {
		return nil, herr
	}
	if !isObject(doc) || !isArray(doc.Field("proofs")) {
		return indexed, nil
	}
	for _, entry := range doc.Field("proofs").Arr {
		if d := entry.Field("declaration"); isObject(d) {
			if eh := d.Field("entry_hash"); isString(eh) {
				indexed[lower(eh.Str)] = entry
			}
		}
	}
	return indexed, nil
}

// declarationProofProblem mirrors declaration_proof_problem: is this
// out-of-range declaration sealed? Returns the problem, or "" when the
// audit path, the checkpoint signature and the key window all hold.
func (r *run) declarationProofProblem(proofs map[string]*cjson.Value, entryHash string, record *cjson.Value) string {
	where := "declaration " + textOr(record.Field("stream_slug"), "?") + " sequence " + textOr(record.Field("seq"), "?")
	proof := proofs[entryHash]
	if proof == nil {
		return where + ": sits outside this bundle's range and carries no inclusion proof, so nothing here shows it was ever sealed"
	}
	checkpoint := proof.Field("checkpoint")
	if !isObject(checkpoint) {
		return where + ": its proof carries no checkpoint"
	}
	path := proof.Field("path")
	if !isArray(path) {
		return where + ": its proof is malformed"
	}
	leaf, ok := hexBytes(entryHash)
	if !ok {
		return where + ": its entry hash is not hex"
	}
	var steps []merkle.Step
	for _, step := range path.Arr {
		var siblingHex, side *cjson.Value
		if isObject(step) {
			siblingHex = step.Field("hash")
			side = step.Field("side")
		}
		var sibling []byte
		siblingOK := false
		if isString(siblingHex) {
			sibling, siblingOK = hexBytes(siblingHex.Str)
		}
		if !siblingOK || !(strEq(side, "left") || strEq(side, "right")) {
			return where + ": its audit path is malformed"
		}
		steps = append(steps, merkle.Step{Sibling: sibling, Left: strEq(side, "left")})
	}
	computed := merkle.AuditPath(leaf, steps)
	if lower(text(checkpoint.Field("root"))) != hex.EncodeToString(computed) {
		return where + ": its audit path does not rebuild the checkpoint's Merkle root - the proof does not prove this declaration"
	}

	// The checkpoint itself: hash, signature, trusted key, key window. The
	// preimage takes the checkpoint's own v field, as verify.php does here.
	v := checkpoint.Field("v")
	if nullish(v) {
		v = intValue(1)
	}
	preimage, cerr := cjson.Canonical(checkpointPreimage(v, fieldOrNull(checkpoint, "stream"), fieldOrNull(checkpoint, "from"), fieldOrNull(checkpoint, "to"), fieldOrNull(checkpoint, "root"), fieldOrNull(checkpoint, "prev_checkpoint"), fieldOrNull(checkpoint, "created_at")))
	if cerr != nil {
		return fmt.Sprintf("%s: its sealing checkpoint's fields cannot be canonicalised (%s) - its hash cannot be recomputed", where, cerr.Error())
	}
	declaredHash := lower(text(checkpoint.Field("checkpoint_hash")))
	if declaredHash != sha256Hex(preimage) {
		return where + ": its sealing checkpoint's hash does not recompute from its fields"
	}

	publicKeyHex := lower(text(checkpoint.Field("public_key")))
	signature, sigOK := hexBytes(text(checkpoint.Field("signature")))
	message, msgOK := hexBytes(declaredHash)
	publicKey, pkOK := hexBytes(publicKeyHex)
	valid := sigOK && msgOK && pkOK && len(signature) == 64 && len(publicKey) == 32 && edsig.Verify(publicKey, message, signature)
	if !valid {
		return where + ": its sealing checkpoint's signature does not verify"
	}

	trusted := r.trusted.lookup(publicKeyHex)
	if trusted == nil {
		// Not a redaction failure: the declaration is sealed, under a key
		// the signing identity result already carries once for the bundle.
		return ""
	}
	createdAt, retiredAt := trusted.window()
	for _, problem := range windowProblems(createdAt, retiredAt, text(checkpoint.Field("created_at"))) {
		return where + ": its sealing checkpoint " + problem
	}
	return ""
}
