package verify

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sigilbase/verifier-go/internal/bundle"
	"github.com/sigilbase/verifier-go/internal/cjson"
)

// The collection records of format 1.6 (FORMAT.md, "Collection records"):
// the event actions a connection's receipt stream carries, and the
// resource prefix that marks them. Mirrors check_collection_records in
// verify.php rule for rule.
var collectionActions = map[string]bool{
	"stream.config":      true,
	"collection.receipt": true,
	"stream.gap":         true,
	"stream.gap_healed":  true,
	"stream.settled":     true,
}

const collectionResourcePrefix = "connection-stream:"

var (
	hex64   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dayForm = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// CollectionSummary is what the collection check counted, for the human
// report. It is not part of the JSON document.
type CollectionSummary struct {
	Streams     int
	Receipts    int
	Gaps        int
	Settlements int
	Records     int
}

// collectionHash is collection_hash: a bundle value as a 64-character
// lowercase hex digest, or "" when it is not one.
func collectionHash(v *cjson.Value) string {
	s := lower(text(v))
	if hex64.MatchString(s) {
		return s
	}
	return ""
}

// collectionSame is collection_same: canonical equality of two payload
// values; a value that cannot be canonicalised equals nothing.
func collectionSame(a, b *cjson.Value) bool {
	ca, err := cjson.Canonical(a)
	if err != nil {
		return false
	}
	cb, err := cjson.Canonical(b)
	if err != nil {
		return false
	}
	return string(ca) == string(cb)
}

type collectionGap struct {
	from, to, reason string
	known            bool
	healed           bool
}

type collectionDay struct {
	supplement int64
	seq        int64
	hash       string
}

type collectionStream struct {
	key           string
	configs       int
	recordsStream string
	receipts      int64
	lastHash      string
	lastIndex     int64
	indexKnown    bool
	lastCursor    *cjson.Value
	cursorKnown   bool
	gaps          map[string]*collectionGap
	gapOrder      []string
	days          map[string]collectionDay
	settlements   int
}

// checkCollectionRecords is check_collection_records: a second streaming
// pass over the events, keeping per resource only the head of its receipt
// chain, the gaps it declared and the days it settled. Every failure
// demotes content integrity. Links to records before the range are noted
// and never failed; in a bundle that starts at sequence 1 nothing precedes
// the range, so there every link must resolve.
func (r *run) checkCollectionRecords(b bundle.Reader, rangeFrom int64) (*CollectionSummary, *hardError) {
	anchored := rangeFrom == 1

	var connection *cjson.Value
	if b.IsFile("connection.json") {
		doc, herr := decodeOptional(b, "connection.json")
		if herr != nil {
			return nil, herr
		}
		var role *cjson.Value
		if isObject(doc) {
			role = doc.Field("role")
		}
		if !strEq(role, "records") && !strEq(role, "receipts") {
			r.report(`connection.json is present but malformed - expected an object whose role is "records" or "receipts"`, ResultContent)
		} else {
			connection = doc
			if strEq(role, "records") {
				r.note(fmt.Sprintf("connection.json: these records were collected through a Sigilbase connection; the receipts covering them are in stream [%s], exported separately. The records verify here as any events do; the receipt chain is checked in that bundle.", text(doc.Field("receipt_stream"))))
			}
		}
	}

	streams := map[string]*collectionStream{}
	var order []string
	summary := &CollectionSummary{}
	seen := false

	if !b.IsFile("events.ndjson") {
		return nil, nil
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
		if perr != nil || !isObject(event) {
			continue
		}
		action := event.Field("action")
		resource := event.Field("resource")
		seqV := event.Field("seq")
		if !isString(action) || !collectionActions[action.Str] || !isString(resource) ||
			!strings.HasPrefix(resource.Str, collectionResourcePrefix) || !isInt(seqV) {
			continue
		}
		sequence := seqV.Int

		if !seen {
			r.info("Checking collection records (receipt chains, gaps, settlement)...")
			seen = true
		}

		key := resource.Str[len(collectionResourcePrefix):]
		state, ok := streams[resource.Str]
		if !ok {
			state = &collectionStream{key: key, gaps: map[string]*collectionGap{}, days: map[string]collectionDay{}}
			streams[resource.Str] = state
			order = append(order, resource.Str)
		}

		label := fmt.Sprintf("sequence %d (%s, stream %s)", sequence, action.Str, key)
		entryHash := collectionHash(event.Field("entry_hash"))
		payload := event.Field("payload")
		summary.Records++

		// Rule 6: a redacted record is noted; later records chain from its
		// entry hash, which the chain walk has already verified.
		if strEq(event.Field("payload_state"), "redacted") || nullish(payload) {
			r.note(fmt.Sprintf("%s: the payload is redacted, so this record's links cannot be checked; later records chain from its entry hash", label))
			if action.Str == "collection.receipt" {
				state.receipts++
				state.lastHash = entryHash
				state.indexKnown = false
				state.cursorKnown = false
				summary.Receipts++
			}
			continue
		}

		if !isObject(payload) {
			r.report(fmt.Sprintf("%s: the payload is not an object", label), ResultContent)
			continue
		}

		// Rule 5: nothing precedes a stream's configuration.
		if anchored && action.Str != "stream.config" && state.configs == 0 {
			r.report(fmt.Sprintf("%s: a collection record precedes the stream's configuration (stream.config) in a bundle that starts at sequence 1", label), ResultContent)
		}

		switch action.Str {
		case "stream.config":
			if !intIs(payload.Field("config_version"), 1) {
				r.report(fmt.Sprintf("%s: config_version is not 1", label), ResultContent)
			}
			recordsStream := payload.Field("records_stream")
			switch {
			case !isString(recordsStream) || recordsStream.Str == "":
				r.report(fmt.Sprintf("%s: records_stream is missing", label), ResultContent)
			case state.recordsStream != "" && state.recordsStream != recordsStream.Str:
				r.report(fmt.Sprintf("%s: the configuration names records stream [%s] but an earlier one named [%s]", label, recordsStream.Str, state.recordsStream), ResultContent)
			default:
				state.recordsStream = recordsStream.Str
			}
			state.configs++

		case "collection.receipt":
			summary.Receipts++
			if !intIs(payload.Field("receipt_version"), 1) {
				r.report(fmt.Sprintf("%s: receipt_version is not 1", label), ResultContent)
			}
			indexV := payload.Field("receipt_index")
			indexKnown := isInt(indexV) && indexV.Int >= 1
			var index int64
			if indexKnown {
				index = indexV.Int
			} else {
				r.report(fmt.Sprintf("%s: receipt_index must be a positive integer", label), ResultContent)
			}
			prev := collectionHash(payload.Field("prev_receipt_hash"))
			if prev == "" {
				r.report(fmt.Sprintf("%s: prev_receipt_hash is not a 64-character hex digest", label), ResultContent)
			}
			if collectionHash(payload.Field("page_hash")) == "" {
				r.report(fmt.Sprintf("%s: page_hash is not a 64-character hex digest", label), ResultContent)
			}
			countV := payload.Field("record_count")
			countKnown := isInt(countV) && countV.Int >= 0
			if !countKnown {
				r.report(fmt.Sprintf("%s: record_count must be a non-negative integer", label), ResultContent)
			}
			records := payload.Field("records")
			switch {
			case nullish(records):
				if countKnown && countV.Int != 0 {
					r.report(fmt.Sprintf("%s: record_count is %d but records is null", label, countV.Int), ResultContent)
				}
			case !isObject(records) || !isInt(records.Field("from_sequence")) || !isInt(records.Field("to_sequence")) ||
				records.Field("from_sequence").Int > records.Field("to_sequence").Int:
				r.report(fmt.Sprintf("%s: records must be an object with from_sequence no greater than to_sequence", label), ResultContent)
			case countKnown && countV.Int > records.Field("to_sequence").Int-records.Field("from_sequence").Int+1:
				r.report(fmt.Sprintf("%s: record_count %d exceeds the records range", label, countV.Int), ResultContent)
			}
			if d := payload.Field("duplicates_seen"); !isInt(d) || d.Int < 0 {
				r.report(fmt.Sprintf("%s: duplicates_seen must be a non-negative integer", label), ResultContent)
			}
			if cb := payload.Field("collected_by"); !strEq(cb, "tenant") && !strEq(cb, "sigilbase") {
				r.report(fmt.Sprintf("%s: collected_by must be tenant or sigilbase", label), ResultContent)
			}
			if m := payload.Field("method"); !isString(m) || m.Str == "" {
				r.report(fmt.Sprintf("%s: method is missing", label), ResultContent)
			}

			// Rule 2: the chain.
			switch {
			case state.lastHash != "":
				if prev != "" && prev != state.lastHash {
					r.report(fmt.Sprintf("%s: prev_receipt_hash does not name the previous receipt's entry hash - the receipt chain is broken here", label), ResultContent)
				}
				if indexKnown && state.indexKnown && index != state.lastIndex+1 {
					r.report(fmt.Sprintf("%s: receipt_index %d follows receipt %d - a receipt is missing or repeated", label, index, state.lastIndex), ResultContent)
				}
				if state.cursorKnown && !collectionSame(fieldOrNull(payload, "cursor_before"), state.lastCursor) {
					r.report(fmt.Sprintf("%s: cursor_before does not equal the previous receipt's cursor_after - a collection is missing between them", label), ResultContent)
				}
			case indexKnown && index == 1:
				if prev != "" && prev != zeroHash {
					r.report(fmt.Sprintf("%s: the first receipt of a stream must name the zero hash as prev_receipt_hash", label), ResultContent)
				}
			case indexKnown:
				if anchored {
					r.report(fmt.Sprintf("%s: receipt %d is the first for this stream in a bundle that starts at sequence 1 - receipts 1 to %d are missing", label, index, index-1), ResultContent)
				} else {
					r.note(fmt.Sprintf("%s: the receipt chain enters this range at receipt %d; its link to receipt %d lies before the range and is not checked here", label, index, index-1))
				}
			}

			state.receipts++
			state.lastHash = entryHash
			state.lastIndex = index
			state.indexKnown = indexKnown
			cursorAfter, hasCursor := payload.Obj.Get("cursor_after")
			state.lastCursor = cursorAfter
			state.cursorKnown = hasCursor

		case "stream.gap":
			summary.Gaps++
			if !intIs(payload.Field("gap_version"), 1) {
				r.report(fmt.Sprintf("%s: gap_version is not 1", label), ResultContent)
			}
			gapID := ""
			if g := payload.Field("gap_id"); isString(g) && g.Str != "" {
				gapID = g.Str
			} else {
				r.report(fmt.Sprintf("%s: gap_id is missing", label), ResultContent)
			}
			from, fromOK := parseRFC3339Value(payload.Field("from"))
			to, toOK := parseRFC3339Value(payload.Field("to"))
			if !fromOK || !toOK {
				r.report(fmt.Sprintf("%s: from and to must be RFC 3339 timestamps", label), ResultContent)
			} else if !from.Before(to) {
				r.report(fmt.Sprintf("%s: from must precede to", label), ResultContent)
			}
			if reason := payload.Field("reason"); !isString(reason) || reason.Str == "" {
				r.report(fmt.Sprintf("%s: reason is missing", label), ResultContent)
			}

			// Rule 3: where the gap sits in the chain.
			after := collectionHash(payload.Field("declared_after_receipt_hash"))
			switch {
			case after == "":
				r.report(fmt.Sprintf("%s: declared_after_receipt_hash is not a 64-character hex digest", label), ResultContent)
			case state.lastHash != "":
				if after != state.lastHash {
					r.report(fmt.Sprintf("%s: declared_after_receipt_hash does not name the latest receipt before it - the gap is placed wrongly in the chain", label), ResultContent)
				}
			case anchored:
				if after != zeroHash {
					r.report(fmt.Sprintf("%s: no receipt precedes this gap in a bundle that starts at sequence 1, so declared_after_receipt_hash must be the zero hash", label), ResultContent)
				}
			default:
				r.note(fmt.Sprintf("%s: the receipt this gap was declared after lies before the range and is not checked here", label))
			}

			if gapID != "" {
				if _, dup := state.gaps[gapID]; dup {
					r.report(fmt.Sprintf("%s: gap [%s] is declared twice", label, gapID), ResultContent)
				} else {
					state.gapOrder = append(state.gapOrder, gapID)
				}
				state.gaps[gapID] = &collectionGap{
					from:   text(payload.Field("from")),
					to:     text(payload.Field("to")),
					reason: text(payload.Field("reason")),
					known:  true,
				}
			}

		case "stream.gap_healed":
			g := payload.Field("gap_id")
			switch {
			case !isString(g) || g.Str == "":
				r.report(fmt.Sprintf("%s: gap_id is missing", label), ResultContent)
			case state.gaps[g.Str] != nil:
				state.gaps[g.Str].healed = true
			case anchored:
				r.report(fmt.Sprintf("%s: heals gap [%s], which the chain never declared in a bundle that starts at sequence 1", label, g.Str), ResultContent)
			default:
				r.note(fmt.Sprintf("%s: heals gap [%s], declared before the range; not checked here", label, g.Str))
				state.gaps[g.Str] = &collectionGap{healed: true}
				state.gapOrder = append(state.gapOrder, g.Str)
			}

		case "stream.settled":
			summary.Settlements++
			state.settlements++
			if !intIs(payload.Field("settlement_version"), 1) {
				r.report(fmt.Sprintf("%s: settlement_version is not 1", label), ResultContent)
			}
			day := ""
			if d := payload.Field("day"); isString(d) && dayForm.MatchString(d.Str) {
				day = d.Str
			} else {
				r.report(fmt.Sprintf("%s: day must be a date of the form YYYY-MM-DD", label), ResultContent)
			}
			settledState := ""
			if s := payload.Field("state"); strEq(s, "settled") || strEq(s, "gapped") {
				settledState = s.Str
			} else {
				r.report(fmt.Sprintf("%s: state must be settled or gapped", label), ResultContent)
			}
			supplementV := payload.Field("supplement")
			supplementKnown := isInt(supplementV) && supplementV.Int >= 0
			if !supplementKnown {
				r.report(fmt.Sprintf("%s: supplement must be a non-negative integer", label), ResultContent)
			}

			// Rule 4: the receipt head and count the settlement names.
			receipts := payload.Field("receipts")
			if !isObject(receipts) {
				r.report(fmt.Sprintf("%s: receipts must be an object", label), ResultContent)
			} else {
				head := receipts.Field("last_receipt_hash")
				switch {
				case state.lastHash != "":
					if collectionHash(head) != state.lastHash {
						r.report(fmt.Sprintf("%s: receipts.last_receipt_hash does not name the latest receipt before it", label), ResultContent)
					}
				case anchored:
					if !nullish(head) {
						r.report(fmt.Sprintf("%s: no receipt precedes this settlement in a bundle that starts at sequence 1, so receipts.last_receipt_hash must be null", label), ResultContent)
					}
				default:
					r.note(fmt.Sprintf("%s: the receipt head this settlement names lies before the range and is not checked here", label))
				}
				count := receipts.Field("count")
				switch {
				case !isInt(count) || count.Int < 0:
					r.report(fmt.Sprintf("%s: receipts.count must be a non-negative integer", label), ResultContent)
				case anchored && count.Int != state.receipts, !anchored && count.Int < state.receipts:
					r.report(fmt.Sprintf("%s: receipts.count is %d but %d receipt(s) precede it in the chain", label, count.Int, state.receipts), ResultContent)
				}
			}

			// The gaps it lists, against the gaps the chain declared.
			unhealed := false
			for _, item := range iterValues(payload.Field("gaps")) {
				var itemID *cjson.Value
				if isObject(item) {
					itemID = item.Field("gap_id")
				}
				if !isString(itemID) || itemID.Str == "" {
					r.report(fmt.Sprintf("%s: a listed gap has no gap_id", label), ResultContent)
					continue
				}
				healedV := item.Field("healed")
				healed := false
				if healedV != nil && healedV.Kind == cjson.Bool {
					healed = healedV.Bool
				} else {
					r.report(fmt.Sprintf("%s: gap [%s] is listed without a boolean healed", label, itemID.Str), ResultContent)
				}
				if !healed {
					unhealed = true
				}
				known := state.gaps[itemID.Str]
				if known == nil {
					if anchored {
						r.report(fmt.Sprintf("%s: lists gap [%s], which the chain never declared", label, itemID.Str), ResultContent)
					} else {
						r.note(fmt.Sprintf("%s: gap [%s] was declared before the range and is not checked here", label, itemID.Str))
					}
					continue
				}
				if known.known && (text(item.Field("from")) != known.from || text(item.Field("to")) != known.to || text(item.Field("reason")) != known.reason) {
					r.report(fmt.Sprintf("%s: gap [%s] is listed with bounds or a reason that differ from its declaration", label, itemID.Str), ResultContent)
				}
				if known.healed != healed {
					word := "unhealed"
					if healed {
						word = "healed"
					}
					r.report(fmt.Sprintf("%s: gap [%s] is listed as %s but the chain says otherwise", label, itemID.Str, word), ResultContent)
				}
			}
			if settledState != "" && ((settledState == "gapped") != unhealed) {
				say := "settled"
				if unhealed {
					say = "gapped"
				}
				r.report(fmt.Sprintf("%s: state is %s but the listed gaps say %s", label, settledState, say), ResultContent)
			}

			// Supplements chain to the settlement they add to.
			previous := payload.Field("previous_settlement")
			if day != "" && supplementKnown {
				prior, hasPrior := state.days[day]
				switch {
				case supplementV.Int == 0:
					if !nullish(previous) {
						r.report(fmt.Sprintf("%s: a first settlement must not name a previous one", label), ResultContent)
					}
					if hasPrior {
						r.report(fmt.Sprintf("%s: day %s was already settled at sequence %d", label, day, prior.seq), ResultContent)
					}
				case !isObject(previous) || !isInt(previous.Field("sequence")) || collectionHash(previous.Field("entry_hash")) == "":
					r.report(fmt.Sprintf("%s: a supplement must name the previous settlement by sequence and entry hash", label), ResultContent)
				case hasPrior:
					if previous.Field("sequence").Int != prior.seq || collectionHash(previous.Field("entry_hash")) != prior.hash || supplementV.Int != prior.supplement+1 {
						r.report(fmt.Sprintf("%s: supplement %d for day %s does not follow the previous settlement in the chain", label, supplementV.Int, day), ResultContent)
					}
				case previous.Field("sequence").Int >= rangeFrom:
					r.report(fmt.Sprintf("%s: names a previous settlement at sequence %d, inside the range, that the chain does not hold for day %s", label, previous.Field("sequence").Int, day), ResultContent)
				default:
					r.note(fmt.Sprintf("%s: supplement %d for day %s follows a settlement before the range; not checked here", label, supplementV.Int, day))
				}
				state.days[day] = collectionDay{supplement: supplementV.Int, seq: sequence, hash: entryHash}
			}
		}
	}
	if lerr := lines.Err(); lerr != nil {
		return nil, hard("could not read [events.ndjson]", 1)
	}

	if !seen {
		if connection != nil && strEq(connection.Field("role"), "receipts") {
			r.report("connection.json says this is a connection's receipt stream, but the range holds no collection record at all", ResultContent)
		}
		return nil, nil
	}

	// Rule 7: connection.json against the chain.
	if connection != nil && strEq(connection.Field("role"), "receipts") {
		listed := map[string]string{}
		var listedOrder []string
		for _, item := range iterValues(connection.Field("record_streams")) {
			if !isObject(item) || !isString(item.Field("stream_key")) || !isString(item.Field("stream")) {
				continue
			}
			k := item.Field("stream_key").Str
			if _, dup := listed[k]; !dup {
				listedOrder = append(listedOrder, k)
			}
			listed[k] = item.Field("stream").Str
		}
		for _, resource := range order {
			state := streams[resource]
			if state.recordsStream == "" {
				continue
			}
			slug, ok := listed[state.key]
			switch {
			case !ok:
				r.report(fmt.Sprintf("connection.json does not list stream [%s], whose configuration is in the range - the metadata contradicts the chain", state.key), ResultContent)
			case slug != state.recordsStream:
				r.report(fmt.Sprintf("connection.json names records stream [%s] for [%s] but the chain's configuration names [%s] - the metadata contradicts the chain", slug, state.key, state.recordsStream), ResultContent)
			}
		}
		if anchored {
			for _, k := range listedOrder {
				if _, ok := streams[collectionResourcePrefix+k]; !ok {
					r.report(fmt.Sprintf("connection.json lists stream [%s] but a bundle that starts at sequence 1 holds no configuration for it", k), ResultContent)
				}
			}
		}
	} else if connection == nil {
		r.note("connection.json is absent; the collection records were checked from the chain alone")
	}

	for _, resource := range order {
		state := streams[resource]
		r.note(fmt.Sprintf("stream %s: %d receipt(s) chained, %d gap(s) declared, %d settlement record(s)", state.key, state.receipts, len(state.gaps), state.settlements))
	}

	summary.Streams = len(streams)
	return summary, nil
}

// intIs is "($x ?? null) === n".
func intIs(v *cjson.Value, n int64) bool {
	return isInt(v) && v.Int == n
}
