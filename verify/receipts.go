package verify

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sigilbase/verifier-go/internal/bundle"
	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/internal/edsig"
	"github.com/sigilbase/verifier-go/internal/phpcompat"
	"github.com/sigilbase/verifier-go/keys"
)

// Receipts and registries (format 1.7, verifier 1.8; FORMAT.md, "Receipts
// and registries"). Every function here mirrors the verify.php function
// named in its comment, rule for rule, because the reason code, the result
// each failure demotes and the number of failures and notes are all part
// of what the differential holds the two to.

// ReceiptVersion is the receipt body's v, and the domain prefix of the bytes
// a receipt signature covers.
const ReceiptVersion = "sigilbase-receipt/1"

// windowCloseGrace is WINDOW_CLOSE_GRACE_SECONDS: a window closed more than
// this long before the log's last record must have its close record.
const windowCloseGrace = 300 * time.Second

// registryOutcomes is REGISTRY_OUTCOMES.
var registryOutcomes = map[string]bool{
	"accepted": true, "replay": true, "conflict": true, "invalid": true,
	"refused_early": true, "refused_late": true, "refused_scope": true,
	"refused_paused": true, "refused_archived": true, "throttled": true,
}

// The exact patterns verify.php applies with preg_match and \A...\z: no
// trailing newline is let through (Go's ^ and $ without the m flag are
// already \A and \z).
var (
	hexAny64Pattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	hexLow64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func pregMatch(re *regexp.Regexp, s string) bool { return re.MatchString(s) }

// ---- receipt keys -------------------------------------------------------

// ReceiptKeySet is a trusted receipt key set (FORMAT.md, "Receipt keys"),
// keyed by key_id, the lowercase hex SHA-256 of the raw public key.
type ReceiptKeySet struct {
	keys map[string]receiptKey
}

type receiptKey struct {
	publicKey string
	createdAt *cjson.Value
	retiredAt *cjson.Value
}

// Len is the number of keys in the set.
func (s *ReceiptKeySet) Len() int { return len(s.keys) }

// EmbeddedReceiptKeys is the set compiled into this build from
// keys/receipt-keys.json (verify.php's TRUSTED_RECEIPT_KEYS).
func EmbeddedReceiptKeys() *ReceiptKeySet {
	set, err := parseReceiptKeySet(keys.ReceiptKeysJSON, "the built-in receipt key set")
	if err != nil {
		// Part of the build and held to shape by a test: an unreadable
		// embed is a broken build, not a runtime condition.
		panic("keys/receipt-keys.json: " + err.Error())
	}
	return set
}

// LoadReceiptKeyFile reads a --receipt-keys file exactly as verify.php's
// load_receipt_key_file does. The error message is the one verify.php
// prints, and the caller exits 2.
func LoadReceiptKeyFile(path string) (*ReceiptKeySet, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("--receipt-keys file [%s] does not exist", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--receipt-keys file [%s] does not exist", path)
	}
	return parseReceiptKeySet(data, fmt.Sprintf("--receipt-keys file [%s]", path))
}

// parseReceiptKeySet decodes a receipt keys document in associative mode
// and applies receipt_key_map: every entry's key_id must be the SHA-256 of
// its public_key, which must be 64 hex characters.
func parseReceiptKeySet(data []byte, source string) (*ReceiptKeySet, error) {
	decoded, err := cjson.ParseAssoc(data)
	if err != nil {
		decoded = nil
	}
	var list *cjson.Value
	if isObject(decoded) {
		list = decoded.Field("keys")
	}
	// In associative mode a JSON object is a PHP array too.
	if !isArray(list) && !isObject(list) {
		return nil, fmt.Errorf(`%s has no "keys" list`, source)
	}
	set := &ReceiptKeySet{keys: map[string]receiptKey{}}
	for _, entry := range iterValues(list) {
		publicKey := entry.Field("public_key")
		keyID := entry.Field("key_id")
		var raw []byte
		rawOK := false
		if isString(publicKey) && pregMatch(hexAny64Pattern, publicKey.Str) {
			raw, rawOK = hexBytes(publicKey.Str)
		}
		if !isString(keyID) || !rawOK {
			return nil, fmt.Errorf("%s has an entry whose key_id is not the SHA-256 of its public_key", source)
		}
		sum := sha256.Sum256(raw)
		want := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(want), []byte(lower(keyID.Str))) != 1 {
			return nil, fmt.Errorf("%s has an entry whose key_id is not the SHA-256 of its public_key", source)
		}
		set.keys[lower(keyID.Str)] = receiptKey{
			publicKey: lower(publicKey.Str),
			createdAt: entry.Field("created_at"),
			retiredAt: entry.Field("retired_at"),
		}
	}
	return set, nil
}

// ---- the run's reason ---------------------------------------------------

// setReason is set_reason for a failed check: the first failure's code is
// the run's reason.
func (r *run) setReason(code string) {
	if r.reason == nil {
		c := code
		r.reason = &c
	}
}

// setUnconfirmedReason is set_reason(..., unconfirmed: true): the first
// unconfirmed check's code, the run's reason when nothing failed.
func (r *run) setUnconfirmedReason(code string) {
	if r.unconfirmedReason == nil {
		c := code
		r.unconfirmedReason = &c
	}
}

// runReason is run_reason: the first failure's code, else the first
// unconfirmed check's, else nil.
func (r *run) runReason() *string {
	if r.reason != nil {
		return r.reason
	}
	return r.unconfirmedReason
}

// reasonFail is reason_fail: a failed receipt or registry check, against
// content integrity unless a result is named.
func (r *run) reasonFail(code, message, result string) {
	r.setReason(code)
	r.report(code+": "+message, result)
}

// ---- receipts -------------------------------------------------------------

// receiptDocument is a receipt as read: its body and its signature.
type receiptDocument struct {
	body      *cjson.Value
	signature string
}

// readReceiptDocument is read_receipt_document: {body, signature}, or the
// API's envelope {receipt: {body, signature}, receipt_pending}. Nil, with
// RECEIPT_SHAPE reported, when it is neither; a hard error when the path is
// not a file.
func (r *run) readReceiptDocument(path string) (*receiptDocument, *hardError) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, hard(fmt.Sprintf("receipt [%s] does not exist", path), ExitError)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, hard(fmt.Sprintf("receipt [%s] does not exist", path), ExitError)
	}
	decoded := decode(data)
	if isObject(decoded) && isObject(decoded.Field("receipt")) {
		decoded = decoded.Field("receipt")
	}
	if !isObject(decoded) || !isObject(decoded.Field("body")) || !isString(decoded.Field("signature")) {
		r.reasonFail("RECEIPT_SHAPE", fmt.Sprintf("receipt [%s] is not a {body, signature} document", path), ResultContent)
		return nil, nil
	}
	return &receiptDocument{body: decoded.Field("body"), signature: decoded.Field("signature").Str}, nil
}

// requestDigest is request_digest (FORMAT.md, "Receipts"): an event's
// fields, its payload hash and the commitment key it was accepted for.
func requestDigest(event *cjson.Value, commitmentKey *string) string {
	obj := cjson.NewObject()
	obj.Set("occurred_at", stringValue(text(event.Field("occurred_at"))))
	obj.Set("actor", stringValue(text(event.Field("actor"))))
	obj.Set("action", stringValue(text(event.Field("action"))))
	if res := event.Field("resource"); isString(res) {
		obj.Set("resource", res)
	} else {
		obj.Set("resource", &cjson.Value{Kind: cjson.Null})
	}
	obj.Set("payload_sha256", stringValue(text(event.Field("payload_hash"))))
	if commitmentKey != nil {
		obj.Set("commitment_key", stringValue(*commitmentKey))
	} else {
		obj.Set("commitment_key", &cjson.Value{Kind: cjson.Null})
	}
	canon, err := cjson.Canonical(&cjson.Value{Kind: cjson.Object, Obj: obj})
	if err != nil {
		// Strings and null only: canonicalisation cannot fail.
		return ""
	}
	return "sha256:" + sha256Hex(canon)
}

// isDigest is is_digest.
func isDigest(v *cjson.Value) bool {
	return isString(v) && pregMatch(digestPattern, v.Str)
}

// stringOrNil is "is_string($x) ? $x : null".
func stringOrNil(v *cjson.Value) *string {
	if !isString(v) {
		return nil
	}
	s := v.Str
	return &s
}

// hasMember is property_exists on a decoded object.
func hasMember(v *cjson.Value, key string) bool {
	if !isObject(v) {
		return false
	}
	_, ok := v.Obj.Get(key)
	return ok
}

// receiptShapeProblems is receipt_shape_problems, in field order.
func receiptShapeProblems(body *cjson.Value) []string {
	var problems []string
	if !strEq(body.Field("v"), ReceiptVersion) {
		problems = append(problems, "v is not "+ReceiptVersion)
	}
	for _, field := range []string{"tenant", "stream", "credential"} {
		if v := body.Field(field); !isString(v) || v.Str == "" {
			problems = append(problems, field+" is not a non-empty string")
		}
	}
	if o := body.Field("outcome"); !isString(o) || !registryOutcomes[o.Str] {
		problems = append(problems, "outcome is not one the format names")
	}
	if !isDigest(body.Field("request_digest")) {
		problems = append(problems, "request_digest is not a sha256: digest")
	}
	if !strEq(body.Field("digest_kind"), "canonical") && !strEq(body.Field("digest_kind"), "raw") {
		problems = append(problems, "digest_kind is neither canonical nor raw")
	}
	if k := body.Field("key_id"); !isString(k) || !pregMatch(hexLow64Pattern, k.Str) {
		problems = append(problems, "key_id is not 64 hex characters")
	}
	accepted := body.Field("accepted")
	if !hasMember(body, "accepted") {
		problems = append(problems, "accepted is missing")
	} else if !nullish(accepted) {
		seq, entry := accepted.Field("sequence"), accepted.Field("entry_hash")
		if !isObject(accepted) || !isInt(seq) || seq.Int < 1 ||
			!isString(entry) || !pregMatch(hexLow64Pattern, entry.Str) ||
			!isDigest(accepted.Field("request_digest")) {
			problems = append(problems, "accepted is neither null nor {sequence, entry_hash, request_digest}")
		}
	}
	if hasMember(body, "decision_seq") {
		if d := body.Field("decision_seq"); !isInt(d) || d.Int < 1 {
			problems = append(problems, "decision_seq is not a positive integer")
		}
	}
	if hasMember(body, "commitment_key") {
		if c := body.Field("commitment_key"); !nullish(c) && !isString(c) {
			problems = append(problems, "commitment_key is neither a string nor null")
		}
	}
	if hasMember(body, "idempotency_key") && !isString(body.Field("idempotency_key")) {
		problems = append(problems, "idempotency_key is not a string")
	}
	if hasMember(body, "policy_hash") && !isDigest(body.Field("policy_hash")) {
		problems = append(problems, "policy_hash is not a sha256: digest")
	}
	if hasMember(body, "reasons") {
		reasons := body.Field("reasons")
		ok := isArray(reasons)
		if ok {
			for _, reason := range reasons.Arr {
				if !isString(reason) {
					ok = false
				}
			}
		}
		if !ok {
			problems = append(problems, "reasons is not a list of strings")
		}
	}
	receivedAt, receivedOK := parseRFC3339Value(body.Field("received_at"))
	_, sealOK := parseRFC3339Value(body.Field("seal_by"))
	signedAt, signedOK := parseRFC3339Value(body.Field("signed_at"))
	if !receivedOK || !sealOK || !signedOK {
		problems = append(problems, "received_at, seal_by and signed_at are not all RFC 3339 times")
	} else if signedAt.Before(receivedAt) {
		problems = append(problems, "signed_at is earlier than received_at")
	}
	return problems
}

// checkReceipt is check_receipt: shape, key, signature and the key's window
// at signed_at. True when the receipt is the operator's own signed
// statement; false when it failed, or when its key is not one this run
// trusts (unconfirmed).
func (r *run) checkReceipt(body *cjson.Value, signature, label string) bool {
	if problems := receiptShapeProblems(body); len(problems) > 0 {
		r.reasonFail("RECEIPT_SHAPE", label+": "+strings.Join(problems, "; "), ResultContent)
		return false
	}

	keyID := body.Field("key_id").Str
	key, ok := r.receiptKeys.keys[keyID]
	if !ok {
		r.setUnconfirmedReason("RECEIPT_KEY_UNKNOWN")
		r.unconfirmed(fmt.Sprintf("RECEIPT_KEY_UNKNOWN: %s is signed by receipt key %s, which is not in the trusted receipt key set", label, keyID), ResultIdentity)
		return false
	}

	valid := false
	if raw, ok := phpcompat.Base64Strict(signature); ok && len(raw) == 64 {
		if canon, err := cjson.Canonical(body); err == nil {
			publicKey, _ := hexBytes(key.publicKey)
			message := append([]byte(ReceiptVersion+"\n"), canon...)
			valid = edsig.Verify(publicKey, message, raw)
		}
	}
	if !valid {
		r.reasonFail("RECEIPT_SIGNATURE", fmt.Sprintf("%s: the signature does not verify against receipt key %s", label, keyID), ResultContent)
		return false
	}

	signedAt, _ := parseRFC3339Value(body.Field("signed_at"))
	outside := false
	if !nullish(key.createdAt) {
		createdAt, ok := parseRFC3339Value(key.createdAt)
		if !ok || signedAt.Before(createdAt) {
			outside = true
		}
	}
	if !nullish(key.retiredAt) {
		retiredAt, ok := parseRFC3339Value(key.retiredAt)
		if !ok || !signedAt.Before(retiredAt) {
			outside = true
		}
	}
	if outside {
		r.reasonFail("RECEIPT_KEY_WINDOW", fmt.Sprintf("%s: signed at %s, outside receipt key %s's active window", label, text(body.Field("signed_at")), keyID), ResultIdentity)
		return false
	}
	return true
}

// ---- verified bundles, read back ---------------------------------------

// verifiedCheckpoint is one checkpoint's range and time, as
// load_verified_bundle reads them.
type verifiedCheckpoint struct {
	from, to  int64
	createdAt string
}

// verifiedBundle is load_verified_bundle's result: the manifest, the
// events by sequence (order keeps PHP's array insertion order) and the
// checkpoints.
type verifiedBundle struct {
	manifest    *cjson.Value
	events      map[int64]*cjson.Value
	order       []int64
	checkpoints []verifiedCheckpoint
}

func (v *verifiedBundle) event(seq int64) *cjson.Value {
	if v == nil {
		return nil
	}
	return v.events[seq]
}

// loadVerifiedBundle is load_verified_bundle, called only after
// verifyBundle passed the bundle, so the events are the authenticated ones.
func loadVerifiedBundle(target string) (*verifiedBundle, *hardError) {
	b, herr := bundle.Open(target)
	if herr != nil {
		return nil, herr
	}
	defer b.Close()

	manifestBytes, herr := readRequired(b, "manifest.json")
	if herr != nil {
		return nil, herr
	}
	view := &verifiedBundle{manifest: decode(manifestBytes), events: map[int64]*cjson.Value{}}
	if !isObject(view.manifest) {
		view.manifest = &cjson.Value{Kind: cjson.Object, Obj: cjson.NewObject()}
	}

	if !b.IsFile("events.ndjson") {
		return nil, hard("could not read [events.ndjson]", 1)
	}
	f, err := b.Open("events.ndjson")
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
		event, perr := cjson.Parse(line)
		if perr != nil || !isObject(event) || !isInt(event.Field("seq")) {
			continue
		}
		seq := event.Field("seq").Int
		if _, seen := view.events[seq]; !seen {
			view.order = append(view.order, seq)
		}
		view.events[seq] = event
	}
	if lines.Err() != nil {
		return nil, hard("could not read [events.ndjson]", 1)
	}

	checkpointBytes, herr := readRequired(b, "checkpoints.json")
	if herr != nil {
		return nil, herr
	}
	if doc := decode(checkpointBytes); isObject(doc) {
		for _, cp := range iterValues(doc.Field("checkpoints")) {
			if isObject(cp) {
				view.checkpoints = append(view.checkpoints, verifiedCheckpoint{
					from:      intCast(cp.Field("from")),
					to:        intCast(cp.Field("to")),
					createdAt: text(cp.Field("created_at")),
				})
			}
		}
	}
	return view, nil
}

// manifestPublicID is manifest_public_id.
func manifestPublicID(manifest *cjson.Value) (string, bool) {
	if s := manifest.Field("stream"); isObject(s) && isString(s.Field("public_id")) {
		return s.Field("public_id").Str, true
	}
	return "", false
}

// manifestLogFor is manifest_log_for.
func manifestLogFor(manifest *cjson.Value) (string, bool) {
	if f := manifest.Field("decision_log_for"); isObject(f) && isString(f.Field("public_id")) {
		return f.Field("public_id").Str, true
	}
	return "", false
}

// sealedByDeadline is sealed_by_deadline: whether the first checkpoint
// covering a sequence was signed no later than seal_by. The second result
// is false when no checkpoint in the bundle covers it.
func sealedByDeadline(checkpoints []verifiedCheckpoint, sequence int64, sealBy string) (bool, bool) {
	for _, cp := range checkpoints {
		if cp.from <= sequence && sequence <= cp.to {
			createdAt, ok1 := parseRFC3339(cp.createdAt)
			deadline, ok2 := parseRFC3339(sealBy)
			return ok1 && ok2 && !createdAt.After(deadline), true
		}
	}
	return false, false
}

// decisionRecordDifferences is decision_record_differences: the fields in
// which a decision record does not say what a receipt says.
func decisionRecordDifferences(record, body *cjson.Value) []string {
	var differences []string
	if !strEq(record.Field("action"), "ingress."+text(body.Field("outcome"))) {
		differences = append(differences, "action")
	}
	payload := record.Field("payload")
	if !isObject(payload) {
		return append(differences, "payload")
	}
	for _, field := range []string{"outcome", "request_digest", "digest_kind", "credential", "commitment_key", "policy_hash"} {
		if !strictEqual(payload.Field(field), body.Field(field)) {
			differences = append(differences, field)
		}
	}
	if text(record.Field("received_at")) != text(body.Field("received_at")) {
		differences = append(differences, "received_at")
	}
	return differences
}

// checkReceiptSubject is check_receipt_subject: the receipt against the
// records it names in the bundles given. It returns checked or
// not_checked.
func (r *run) checkReceiptSubject(body *cjson.Value, stream, log *verifiedBundle) string {
	checked, unchecked := false, false
	accepted := body.Field("accepted")
	commitmentKey := stringOrNil(body.Field("commitment_key"))

	// The decision record.
	if d := body.Field("decision_seq"); isInt(d) {
		record := log.event(d.Int)
		if record == nil {
			unchecked = true
			r.note(fmt.Sprintf("the decision record at sequence %d is not in a bundle given; not checked", d.Int))
		} else {
			checked = true
			if differences := decisionRecordDifferences(record, body); len(differences) > 0 {
				r.reasonFail("RECEIPT_SUBJECT", fmt.Sprintf("the decision record at sequence %d differs from the receipt in: %s", d.Int, strings.Join(differences, ", ")), ResultContent)
			}
		}
	}

	// The accepted event.
	if !nullish(accepted) {
		seq := accepted.Field("sequence").Int
		event := stream.event(seq)
		if event == nil {
			unchecked = true
			r.note(fmt.Sprintf("the event at sequence %d is not in a bundle given; not checked", seq))
		} else {
			checked = true
			switch {
			case text(event.Field("entry_hash")) != accepted.Field("entry_hash").Str:
				r.reasonFail("RECEIPT_SUBJECT", fmt.Sprintf("the event at sequence %d does not carry the entry hash the receipt names", seq), ResultContent)
			case requestDigest(event, commitmentKey) != accepted.Field("request_digest").Str:
				r.reasonFail("RECEIPT_SUBJECT", fmt.Sprintf("the event at sequence %d does not have the request digest the receipt names", seq), ResultContent)
			case strEq(body.Field("outcome"), "accepted") && text(event.Field("received_at")) != text(body.Field("received_at")):
				r.reasonFail("RECEIPT_SUBJECT", fmt.Sprintf("the accepted event at sequence %d was received at a different time from the receipt's", seq), ResultContent)
			}
		}
	}

	// The seal deadline: the accepted event for an acceptance, and for a
	// standard stream's replay (one without decision_seq); the decision
	// record for everything a log records, a registry's replay included.
	outcome := text(body.Field("outcome"))
	deadlineOnEvent := !nullish(accepted) &&
		(outcome == "accepted" || (outcome == "replay" && !isInt(body.Field("decision_seq"))))
	view := log
	var sequence *cjson.Value = body.Field("decision_seq")
	if deadlineOnEvent {
		view = stream
		sequence = accepted.Field("sequence")
	}
	if view != nil && isInt(sequence) && view.event(sequence.Int) != nil {
		sealBy := text(body.Field("seal_by"))
		sealed, covered := sealedByDeadline(view.checkpoints, sequence.Int, sealBy)
		if !covered {
			unchecked = true
			r.note(fmt.Sprintf("no checkpoint in the bundle seals sequence %d; the seal deadline is not checked", sequence.Int))
		} else if !sealed {
			r.reasonFail("MSD_BREACH", fmt.Sprintf("sequence %d was sealed by a checkpoint signed after seal_by %s", sequence.Int, sealBy), ResultContent)
		}
	}

	if checked && !unchecked {
		return "checked"
	}
	return "not_checked"
}

// ---- --receipt ------------------------------------------------------------

// ReceiptSummary is the document's receipt: what the receipt says, as
// read, and whether the records it names were checked.
type ReceiptSummary struct {
	KeyID       *string `json:"key_id"`
	Stream      *string `json:"stream"`
	Outcome     *string `json:"outcome"`
	DecisionSeq *int64  `json:"decision_seq"`
	ReceivedAt  *string `json:"received_at"`
	SealBy      *string `json:"seal_by"`
	Subject     string  `json:"subject"`
}

// Receipt checks one receipt and, given bundles (at most two: the stream's
// and its decision log's), the records it names (verify.php's --receipt
// mode).
func Receipt(receiptPath string, targets []string, opts Options) *Report {
	r := newRun(&opts)
	rep := r.newReport()
	rep.Mode = "receipt"
	for _, t := range targets {
		rep.BundleSHA256 = append(rep.BundleSHA256, pathHash(t))
	}
	rep.ReceiptPath = receiptPath
	rep.ReceiptKeysSource = r.receiptKeysSource

	doc, herr := r.readReceiptDocument(receiptPath)
	if herr != nil {
		return r.finishHard(rep, herr)
	}
	var streamID *cjson.Value
	if doc != nil {
		streamID = doc.body.Field("stream")
	}

	bundles := []BundleInfo{}
	var streamView, logView *verifiedBundle
	for _, target := range targets {
		r.info(fmt.Sprintf("=== Bundle: %s ===", target))
		before := len(r.failures)
		result, herr := r.verifyBundle(target, opts.SkipAnchors, nil, nil)
		if herr != nil {
			return r.finishHard(rep, herr)
		}
		bundles = append(bundles, BundleInfo{Path: target, Stream: result.streamID, Range: Range{From: result.rangeFrom, To: result.rangeTo}})
		if len(r.failures) > before {
			r.setReason("BUNDLE")
			r.note(fmt.Sprintf("bundle [%s] does not verify; the receipt is not checked against it", target))
			continue
		}
		view, herr := loadVerifiedBundle(target)
		if herr != nil {
			return r.finishHard(rep, herr)
		}
		logFor, isLog := manifestLogFor(view.manifest)
		publicID, hasID := manifestPublicID(view.manifest)
		switch {
		case isString(streamID) && isLog && logFor == streamID.Str:
			logView = view
		case isString(streamID) && hasID && publicID == streamID.Str:
			streamView = view
		default:
			return r.finishHard(rep, hard(fmt.Sprintf("bundle [%s] is neither the receipt's stream nor its decision log (no matching public_id)", target), ExitError))
		}
	}

	r.info("Checking the receipt...")
	subject := "not_checked"
	if doc != nil {
		body := doc.body
		if r.checkReceipt(body, doc.signature, "the receipt") && len(targets) > 0 {
			subject = r.checkReceiptSubject(body, streamView, logView)
		}
		summary := &ReceiptSummary{
			KeyID:      stringOrNil(body.Field("key_id")),
			Stream:     stringOrNil(body.Field("stream")),
			Outcome:    stringOrNil(body.Field("outcome")),
			ReceivedAt: stringOrNil(body.Field("received_at")),
			SealBy:     stringOrNil(body.Field("seal_by")),
			Subject:    subject,
		}
		if d := body.Field("decision_seq"); isInt(d) {
			n := d.Int
			summary.DecisionSeq = &n
		}
		rep.Receipt = summary
	}

	rep.Bundles = bundles
	rep.Reason = r.runReason()
	return r.finish(rep, r.results.exitCode())
}

// ---- --reconcile ----------------------------------------------------------

// CountMap is a count per name in first-appearance order. It encodes as a
// JSON object, {} when empty, as verify.php's (object) cast does.
type CountMap struct {
	Keys   []string
	Values map[string]int64
}

func (c *CountMap) add(key string) {
	if c.Values == nil {
		c.Values = map[string]int64{}
	}
	if _, seen := c.Values[key]; !seen {
		c.Keys = append(c.Keys, key)
	}
	c.Values[key]++
}

// MarshalJSON writes the counts in first-appearance order.
func (c CountMap) MarshalJSON() ([]byte, error) {
	return marshalOrdered(c.Keys, func(k string) any { return c.Values[k] })
}

// CredentialCounts is the per-credential, per-outcome count map.
type CredentialCounts struct {
	Keys   []string
	Values map[string]*CountMap
}

func (c *CredentialCounts) add(credential, outcome string) {
	if c.Values == nil {
		c.Values = map[string]*CountMap{}
	}
	m, seen := c.Values[credential]
	if !seen {
		m = &CountMap{}
		c.Values[credential] = m
		c.Keys = append(c.Keys, credential)
	}
	m.add(outcome)
}

// MarshalJSON writes the credentials in first-appearance order.
func (c CredentialCounts) MarshalJSON() ([]byte, error) {
	return marshalOrdered(c.Keys, func(k string) any { return c.Values[k] })
}

// ReconcileCounts is the document's counts: the ingress.* records of the
// decision log, in all, per outcome and per credential.
type ReconcileCounts struct {
	Decisions   int64            `json:"decisions"`
	Outcomes    CountMap         `json:"outcomes"`
	Credentials CredentialCounts `json:"credentials"`
}

// registryPolicy is one policy version as read_registry_log reads it.
type registryPolicy struct {
	version     int64
	sequence    int64
	hash        string
	effectiveAt time.Time
	effectiveOK bool
	action      string
	recordedAt  time.Time
	recordedOK  bool
	rules       *cjson.Value
	count       *cjson.Value
	parts       *cjson.Value
	windows     []*cjson.Value
}

// registryAcceptance is one ingress.accepted record.
type registryAcceptance struct {
	sequence   int64
	record     *cjson.Value
	payload    *cjson.Value
	receivedAt time.Time
	receivedOK bool
	key        *string
}

// registryDecision is one ingress.* record with a payload.
type registryDecision struct {
	sequence   int64
	outcome    string
	payload    *cjson.Value
	receivedAt time.Time
	receivedOK bool
}

type registryClose struct {
	sequence int64
	payload  *cjson.Value
}

// registryLog is read_registry_log's result.
type registryLog struct {
	policies     []*registryPolicy
	policyByVer  map[int64]*registryPolicy
	accepted     []*registryAcceptance
	decisions    []*registryDecision
	closes       []registryClose
	counts       ReconcileCounts
	problems     map[string][]string
	lastReceived time.Time
	lastOK       bool
}

// readRegistryLog is read_registry_log: the policies, windows, credentials
// and decisions of a registry's log, read in log order, with the rules
// that depend on that order checked as they go.
func (r *run) readRegistryLog(log *verifiedBundle, order []int64) *registryLog {
	out := &registryLog{policyByVer: map[int64]*registryPolicy{}, problems: map[string][]string{}}
	fail := func(code, message string) { out.problems[code] = append(out.problems[code], message) }

	parts := map[int64][][]*cjson.Value{}
	credentials := map[string]*cjson.Value{}

	for _, sequence := range order {
		record := log.events[sequence]
		action := text(record.Field("action"))
		payload := record.Field("payload")
		if t, ok := parseRFC3339Value(record.Field("received_at")); ok {
			out.lastReceived, out.lastOK = t, true
		}

		// Every ingress.* record is counted, its payload present or not
		// (credential '' when there is none).
		if strings.HasPrefix(action, "ingress.") {
			credential := ""
			if isObject(payload) {
				credential = text(payload.Field("credential"))
			}
			outcome := action[len("ingress."):]
			out.counts.Decisions++
			out.counts.Outcomes.add(outcome)
			out.counts.Credentials.add(credential, outcome)
		}

		if !isObject(payload) {
			if strings.HasPrefix(action, "ingress.") || strings.HasPrefix(action, "policy.") || strings.HasPrefix(action, "credential") {
				r.note(fmt.Sprintf("decision record %d (%s) has no payload in this bundle; it is not read", sequence, action))
			}
			continue
		}

		if action == "policy.committed" || action == "policy.amended" {
			version := payload.Field("version")
			if !isInt(version) || out.policyByVer[version.Int] != nil {
				fail("POLICY_HASH", fmt.Sprintf("record %d: a policy record without a new integer version", sequence))
				continue
			}
			p := &registryPolicy{
				version:  version.Int,
				sequence: sequence,
				action:   action,
				hash:     text(payload.Field("policy_hash")),
				rules:    payload.Field("policy"),
			}
			p.effectiveAt, p.effectiveOK = parseRFC3339Value(payload.Field("effective_at"))
			p.recordedAt, p.recordedOK = parseRFC3339Value(record.Field("received_at"))
			if w := payload.Field("windows"); isObject(w) {
				p.count = w.Field("count")
				p.parts = w.Field("parts")
			}
			out.policies = append(out.policies, p)
			out.policyByVer[version.Int] = p
			parts[version.Int] = [][]*cjson.Value{}
			continue
		}

		if action == "policy.windows" {
			version := payload.Field("version")
			if !isInt(version) || out.policyByVer[version.Int] == nil || !intIs(payload.Field("part"), int64(len(parts[version.Int])+1)) {
				fail("POLICY_HASH", fmt.Sprintf("record %d: a policy.windows record out of order", sequence))
				continue
			}
			parts[version.Int] = append(parts[version.Int], iterValues(payload.Field("windows")))
			continue
		}

		if action == "credentials.snapshot" {
			for _, credential := range iterValues(payload.Field("credentials")) {
				if isObject(credential) && isString(credential.Field("credential")) {
					credentials[credential.Field("credential").Str] = credential.Field("expires_at")
				}
			}
			continue
		}

		if action == "credential.issued" && isString(payload.Field("credential")) {
			credentials[payload.Field("credential").Str] = payload.Field("expires_at")
			continue
		}

		if (action == "credential.revoked" || action == "credential.expired") && isString(payload.Field("credential")) {
			delete(credentials, payload.Field("credential").Str)
			continue
		}

		if action == "window.closed" {
			out.closes = append(out.closes, registryClose{sequence: sequence, payload: payload})
			continue
		}

		if !strings.HasPrefix(action, "ingress.") {
			continue
		}

		outcome := action[len("ingress."):]
		credential := text(payload.Field("credential"))

		decision := &registryDecision{sequence: sequence, outcome: outcome, payload: payload}
		decision.receivedAt, decision.receivedOK = parseRFC3339Value(record.Field("received_at"))
		out.decisions = append(out.decisions, decision)

		if outcome != "accepted" {
			continue
		}

		receivedAt, receivedOK := parseRFC3339Value(record.Field("received_at"))
		expiresAt, known := credentials[credential]
		if !known {
			fail("CREDENTIAL_NOT_VALID", fmt.Sprintf("record %d: accepted from credential [%s], which the log does not show able to submit at that point", sequence, credential))
		} else if !nullish(expiresAt) {
			expiry, expiryOK := parseRFC3339Value(expiresAt)
			if !expiryOK || !receivedOK || !receivedAt.Before(expiry) {
				fail("CREDENTIAL_NOT_VALID", fmt.Sprintf("record %d: accepted from credential [%s] after it expired at %s", sequence, credential, text(expiresAt)))
			}
		}

		out.accepted = append(out.accepted, &registryAcceptance{
			sequence:   sequence,
			record:     record,
			payload:    payload,
			receivedAt: receivedAt,
			receivedOK: receivedOK,
			key:        stringOrNil(payload.Field("commitment_key")),
		})
	}

	// Each policy, its windows joined back, must hash to what it says.
	for _, p := range out.policies {
		var windows []*cjson.Value
		for _, part := range parts[p.version] {
			windows = append(windows, part...)
		}
		if !isObject(p.rules) || !intIs(p.parts, int64(len(parts[p.version]))) || !intIs(p.count, int64(len(windows))) {
			fail("POLICY_HASH", fmt.Sprintf("policy version %d: its windows are not all in the log", p.version))
			p.windows = nil
			continue
		}
		full := cjson.NewObject()
		for i := 0; i < p.rules.Obj.Len(); i++ {
			k, v := p.rules.Obj.At(i)
			full.Set(k, v)
		}
		full.Set("windows", &cjson.Value{Kind: cjson.Array, Arr: append([]*cjson.Value{}, windows...)})
		canon, err := cjson.Canonical(&cjson.Value{Kind: cjson.Object, Obj: full})
		if err != nil || "sha256:"+sha256Hex(canon) != p.hash {
			fail("POLICY_HASH", fmt.Sprintf("policy version %d: the policy and its windows do not hash to its policy_hash", p.version))
		}
		p.windows = windows
	}
	return out
}

// reconcileRegistry is reconcile_registry: the reconcile rules (FORMAT.md,
// "--reconcile"), in order. The run's reason is the first rule that failed.
func (r *run) reconcileRegistry(registry, log *verifiedBundle, receiptPaths []string) (ReconcileCounts, int, *hardError) {
	publicID, hasID := manifestPublicID(registry.manifest)

	// Rule 1: the log is the registry's, and both histories are whole.
	if logFor, isLog := manifestLogFor(log.manifest); !hasID || !isLog || logFor != publicID {
		r.reasonFail("NOT_DECISION_LOG", "the second bundle is not the decision log of the first (decision_log_for does not name its public_id)", ResultContent)
		return ReconcileCounts{}, 0, nil
	}

	logRange, registryRange := log.manifest.Field("range"), registry.manifest.Field("range")
	if !isObject(logRange) || !intIs(logRange.Field("from"), 1) || !isObject(registryRange) || !intIs(registryRange.Field("from"), 1) {
		r.reasonFail("LOG_NOT_DENSE", "both bundles must start at sequence 1: a registry is reconciled over its whole history", ResultContent)
	}

	// Rule 2: the log opens on its policy.
	order := append([]int64{}, log.order...)
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	if first := log.events[1]; first == nil || !strEq(first.Field("action"), "policy.committed") {
		r.reasonFail("FIRST_NOT_POLICY", "decision log event 1 is not policy.committed", ResultContent)
	}

	read := r.readRegistryLog(log, order)

	// Rule 3: every policy is what its hash says.
	for _, message := range read.problems["POLICY_HASH"] {
		r.reasonFail("POLICY_HASH", message, ResultContent)
	}

	// Each version's windows by key, once (a later window of the same key
	// replaces an earlier one).
	windowsByKey := map[int64]map[string]*cjson.Value{}
	for _, p := range read.policies {
		for _, window := range p.windows {
			if isObject(window) && isString(window.Field("key")) {
				if windowsByKey[p.version] == nil {
					windowsByKey[p.version] = map[string]*cjson.Value{}
				}
				windowsByKey[p.version][window.Field("key").Str] = window
			}
		}
	}

	// Rule 4: every policy is this registry's, and amended only as the one
	// before it allows: never under frozen, under notice no sooner than its
	// notice period after the amendment was recorded.
	var previous *registryPolicy
	for _, p := range read.policies {
		if !isObject(p.rules) || !strEq(p.rules.Field("registry"), publicID) {
			r.reasonFail("POLICY_AMENDMENT", fmt.Sprintf("policy version %d is not this registry's (its registry is not %s)", p.version, publicID), ResultContent)
		}
		if previous == nil {
			if p.version != 1 || p.action != "policy.committed" {
				r.reasonFail("POLICY_AMENDMENT", fmt.Sprintf("the first policy record is version %d, %s, not version 1 committed", p.version, p.action), ResultContent)
			}
		} else {
			previousRules := previous.rules
			notice := previousRules.Field("notice_seconds")
			switch {
			case previous.version == math.MaxInt64 || p.version != previous.version+1 || p.action != "policy.amended":
				r.reasonFail("POLICY_AMENDMENT", fmt.Sprintf("policy version %d does not amend version %d", p.version, previous.version), ResultContent)
			case !isObject(previousRules) || !strEq(previousRules.Field("amendment"), "notice") || !isInt(notice):
				r.reasonFail("POLICY_AMENDMENT", fmt.Sprintf("policy version %d cannot be amended (it is not under notice), yet version %d amends it", previous.version, p.version), ResultContent)
			case !p.effectiveOK || !p.recordedOK || effectiveBeforeNotice(p.effectiveAt, p.recordedAt, notice.Int):
				r.reasonFail("POLICY_AMENDMENT", fmt.Sprintf("policy version %d takes effect sooner than the %d s notice its predecessor requires", p.version, notice.Int), ResultContent)
			}
		}
		previous = p
	}

	// Rule 5: every decision follows the policy in force when it was made:
	// the last policy record before it in the log whose effective_at is not
	// after its received_at.
	inForceAt := func(at time.Time, atOK bool, before int64) *registryPolicy {
		var found *registryPolicy
		for _, p := range read.policies {
			if p.sequence < before && atOK && p.effectiveOK && !p.effectiveAt.After(at) {
				found = p
			}
		}
		return found
	}
	for _, decision := range read.decisions {
		payload := decision.payload
		at := decision.receivedAt
		label := fmt.Sprintf("decision %d (%s)", decision.sequence, decision.outcome)
		policy := inForceAt(at, decision.receivedOK, decision.sequence)
		if policy == nil {
			r.reasonFail("DECISION_POLICY", label+" was made with no policy in force", ResultContent)
			continue
		}
		if !strEq(payload.Field("policy_hash"), policy.hash) {
			r.reasonFail("DECISION_POLICY", fmt.Sprintf("%s does not name the hash of policy version %d, in force at its received_at", label, policy.version), ResultContent)
		}

		key := stringOrNil(payload.Field("commitment_key"))
		var window *cjson.Value
		if key != nil {
			window = windowsByKey[policy.version][*key]
		}
		var openAt, closeAt time.Time
		openOK, closeOK := false, false
		if window != nil {
			openAt, openOK = parseRFC3339Value(window.Field("open_at"))
			closeAt, closeOK = parseRFC3339Value(window.Field("close_at"))
		}
		unknownKey := false
		for _, reason := range iterValues(payload.Field("reasons")) {
			if strEq(reason, "unknown_key") {
				unknownKey = true
			}
		}
		var broken bool
		switch decision.outcome {
		case "accepted":
			broken = window == nil || !openOK || !closeOK || at.Before(openAt) || !at.Before(closeAt)
		case "refused_early":
			broken = window == nil || !openOK || !at.Before(openAt)
		case "refused_late":
			broken = window == nil || !closeOK || at.Before(closeAt)
		case "invalid":
			broken = unknownKey && window != nil
		}
		if broken {
			shown := ""
			if key != nil {
				shown = *key
			}
			r.reasonFail("DECISION_POLICY", fmt.Sprintf("%s for key [%s] contradicts the windows of policy version %d", label, shown, policy.version), ResultContent)
		}
	}

	// Rule 6: acceptances and registry events match one to one. An
	// acceptance of an event past the registry bundle's range was made
	// after that bundle was exported: it is noted, not checked.
	var registryTo int64
	if isObject(registryRange) && isInt(registryRange.Field("to")) {
		registryTo = registryRange.Field("to").Int
	}
	claimed := map[int64]int{}
	for _, acceptance := range read.accepted {
		payload := acceptance.payload
		named := payload.Field("accepted")
		if isObject(named) && isInt(named.Field("sequence")) && named.Field("sequence").Int > registryTo {
			r.note(fmt.Sprintf("decision %d accepts registry event %d, after the registry bundle's range: not checked", acceptance.sequence, named.Field("sequence").Int))
			continue
		}
		var event *cjson.Value
		if isObject(named) && isInt(named.Field("sequence")) {
			event = registry.events[named.Field("sequence").Int]
		}
		if event == nil ||
			text(event.Field("entry_hash")) != text(named.Field("entry_hash")) ||
			requestDigest(event, acceptance.key) != text(payload.Field("request_digest")) ||
			text(event.Field("received_at")) != text(acceptance.record.Field("received_at")) {
			r.reasonFail("ACCEPTED_UNMATCHED", fmt.Sprintf("decision %d accepts an event the registry does not hold as it says", acceptance.sequence), ResultContent)
			continue
		}
		claimed[named.Field("sequence").Int]++
	}
	for _, sequence := range registry.order {
		if count := claimed[sequence]; count != 1 {
			r.reasonFail("PARENT_UNMATCHED", fmt.Sprintf("registry event %d is accepted by %d decision(s), not exactly one", sequence, count), ResultContent)
		}
	}

	// Rule 7: one acceptance per key.
	acceptedAt := map[string]*registryAcceptance{}
	for _, acceptance := range read.accepted {
		if acceptance.key == nil {
			r.reasonFail("DOUBLE_ACCEPTANCE", fmt.Sprintf("decision %d accepts without a commitment key", acceptance.sequence), ResultContent)
			continue
		}
		key := *acceptance.key
		if earlier, seen := acceptedAt[key]; seen {
			r.reasonFail("DOUBLE_ACCEPTANCE", fmt.Sprintf("commitment key [%s] is accepted twice (decisions %d and %d)", key, earlier.sequence, acceptance.sequence), ResultContent)
			continue
		}
		acceptedAt[key] = acceptance
	}

	// Rule 8: every window closes once, truthfully.
	policiesByHash := map[string]int64{}
	for _, p := range read.policies {
		policiesByHash[p.hash] = p.version
	}
	closed := map[int64]map[string]bool{}
	for _, c := range read.closes {
		payload := c.payload
		key := text(payload.Field("key"))
		version, hasVersion := policiesByHash[text(payload.Field("policy_hash"))]
		var window *cjson.Value
		if hasVersion {
			window = windowsByKey[version][key]
		}
		if window == nil || text(payload.Field("close_at")) != text(window.Field("close_at")) {
			r.reasonFail("WINDOW_CLOSE", fmt.Sprintf("window.closed %d names key [%s], which its policy does not hold with that close_at", c.sequence, key), ResultContent)
			continue
		}
		if closed[version][key] {
			r.reasonFail("WINDOW_CLOSE", fmt.Sprintf("key [%s] is closed twice under policy version %d", key, version), ResultContent)
			continue
		}
		if closed[version] == nil {
			closed[version] = map[string]bool{}
		}
		closed[version][key] = true

		closeAt, closeOK := parseRFC3339Value(window.Field("close_at"))
		acceptance := acceptedAt[key]
		committed := acceptance != nil && closeOK && acceptance.receivedOK && acceptance.receivedAt.Before(closeAt)
		outcome := payload.Field("outcome")
		named := payload.Field("accepted")
		var wrong bool
		if committed {
			acceptedSequence := acceptance.payload.Field("accepted").Field("sequence")
			if nullish(acceptedSequence) {
				acceptedSequence = &cjson.Value{Kind: cjson.Bool, Bool: false}
			}
			wrong = !strEq(outcome, "committed") || !isObject(named) || !strictEqual(named.Field("sequence"), acceptedSequence)
		} else {
			wrong = !strEq(outcome, "missing") || !nullish(named)
		}
		if wrong {
			shows := "missing"
			if committed {
				shows = "committed"
			}
			r.reasonFail("WINDOW_CLOSE", fmt.Sprintf("window.closed %d says [%s] for key [%s], but the log shows it %s", c.sequence, text(outcome), key, shows), ResultContent)
		}
	}

	if read.lastOK {
		for _, p := range read.policies {
			for _, window := range p.windows {
				if !isObject(window) {
					continue
				}
				closeAt, ok := parseRFC3339Value(window.Field("close_at"))
				if !ok || !closeAt.Add(windowCloseGrace).Before(read.lastReceived) {
					continue
				}
				// The window's key read as text: an array, an object or an
				// absent key is ''.
				windowKey := text(window.Field("key"))
				if closed[p.version][windowKey] {
					continue
				}

				// In force at its close: the latest version effective by then.
				var inForce *registryPolicy
				for _, candidate := range read.policies {
					if candidate.effectiveOK && !candidate.effectiveAt.After(closeAt) {
						inForce = candidate
					}
				}
				if inForce != nil && inForce.version == p.version {
					r.reasonFail("WINDOW_CLOSE", fmt.Sprintf("key [%s] of policy version %d closed at %s and has no window.closed", windowKey, p.version, text(window.Field("close_at"))), ResultContent)
				}
			}
		}
	}

	// Rule 9: every acceptance came from a valid credential.
	for _, message := range read.problems["CREDENTIAL_NOT_VALID"] {
		r.reasonFail("CREDENTIAL_NOT_VALID", message, ResultContent)
	}

	// Rule 10: every receipt is logged, says what its record says, and was
	// sealed by its deadline: the whole --receipt check, against both bundles.
	checked := 0
	for _, path := range receiptPaths {
		label := "receipt " + filepath.Base(path)
		doc, herr := r.readReceiptDocument(path)
		if herr != nil {
			return read.counts, checked, herr
		}
		if doc == nil {
			// Unreadable or not a receipt: RECEIPT_SHAPE, and checked.
			checked++
			continue
		}
		body := doc.body
		if !strEq(body.Field("stream"), publicID) {
			r.note(label + " is for another stream; set aside")
			continue
		}
		checked++
		if !r.checkReceipt(body, doc.signature, label) {
			continue
		}
		var record *cjson.Value
		if d := body.Field("decision_seq"); isInt(d) {
			record = log.events[d.Int]
		}
		differences := []string{"decision_seq"}
		if record != nil {
			differences = decisionRecordDifferences(record, body)
		}
		if len(differences) > 0 {
			r.reasonFail("RECEIPT_NOT_LOGGED", fmt.Sprintf("%s: signed by Sigilbase, but the decision log does not hold it (%s)", label, strings.Join(differences, ", ")), ResultContent)
			continue
		}
		r.checkReceiptSubject(body, registry, log)
	}

	return read.counts, checked, nil
}

// effectiveBeforeNotice is "$effective < $recorded->modify('+N seconds')",
// computed in whole seconds and nanoseconds so that a large notice cannot
// overflow a time.Duration.
func effectiveBeforeNotice(effective, recorded time.Time, notice int64) bool {
	diff := effective.Unix() - recorded.Unix()
	if diff != notice {
		return diff < notice
	}
	return effective.Nanosecond() < recorded.Nanosecond()
}

// receiptFiles lists the receipts of a --receipts directory as verify.php
// does with scandir: every regular file (symbolic links followed, as
// is_file does) whose name ends in .json and does not start with a dot, in
// strcmp order of the name. The directory's own name is never a pattern,
// and a subdirectory is skipped.
func receiptFiles(dir string) ([]string, error) {
	base := strings.TrimRight(dir, `/\`)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		if info, err := os.Stat(base + string(os.PathSeparator) + name); err != nil || !info.Mode().IsRegular() {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	paths := make([]string, len(names))
	for i, n := range names {
		paths[i] = base + string(os.PathSeparator) + n
	}
	return paths, nil
}

// Reconcile checks a registry stream and its decision log against each
// other and, with receiptsDir, the receipts its submitters hold
// (verify.php's --reconcile mode).
func Reconcile(registryPath, logPath string, receiptsDir *string, opts Options) *Report {
	r := newRun(&opts)
	rep := r.newReport()
	rep.Mode = "reconcile"
	rep.BundleSHA256 = []PathHash{pathHash(registryPath), pathHash(logPath)}
	rep.ReceiptKeysSource = r.receiptKeysSource

	var receiptPaths []string
	if receiptsDir != nil {
		info, err := os.Stat(*receiptsDir)
		if err != nil || !info.IsDir() {
			return r.finishHard(rep, hard(fmt.Sprintf("--receipts directory [%s] does not exist", *receiptsDir), ExitError))
		}
		receiptPaths, _ = receiptFiles(*receiptsDir)
	}

	r.info(fmt.Sprintf("=== Registry: %s ===", registryPath))
	registryResult, herr := r.verifyBundle(registryPath, opts.SkipAnchors, nil, nil)
	if herr != nil {
		return r.finishHard(rep, herr)
	}
	r.info(fmt.Sprintf("=== Decision log: %s ===", logPath))
	logResult, herr := r.verifyBundle(logPath, opts.SkipAnchors, nil, nil)
	if herr != nil {
		return r.finishHard(rep, herr)
	}
	r.info("Reconciling...")

	var counts ReconcileCounts
	checked := 0
	if len(r.failures) > 0 {
		r.setReason("BUNDLE")
		r.note("a bundle does not verify, so the registry is not reconciled")
	} else {
		registry, herr := loadVerifiedBundle(registryPath)
		if herr != nil {
			return r.finishHard(rep, herr)
		}
		log, herr := loadVerifiedBundle(logPath)
		if herr != nil {
			return r.finishHard(rep, herr)
		}
		counts, checked, herr = r.reconcileRegistry(registry, log, receiptPaths)
		if herr != nil {
			return r.finishHard(rep, herr)
		}
	}

	rep.Bundles = []BundleInfo{
		{Path: registryPath, Stream: registryResult.streamID, Range: Range{From: registryResult.rangeFrom, To: registryResult.rangeTo}},
		{Path: logPath, Stream: logResult.streamID, Range: Range{From: logResult.rangeFrom, To: logResult.rangeTo}},
	}
	rep.Counts = &counts
	rep.ReceiptsChecked = checked
	rep.Reason = r.runReason()
	return r.finish(rep, r.results.exitCode())
}
