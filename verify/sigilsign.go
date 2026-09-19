package verify

import (
	"fmt"
	"strings"

	"github.com/sigilbase/verifier-go/internal/bundle"
	"github.com/sigilbase/verifier-go/internal/cjson"
)

// collectReferencedSequences mirrors collect_referenced_sequences: every
// integer a document names under a key ending in "sequence", so the
// SigilSign cross-checks can pull just those events out of the stream.
func collectReferencedSequences(node *cjson.Value, into map[int64]bool) {
	if node == nil {
		return
	}
	switch node.Kind {
	case cjson.Array:
		for _, v := range node.Arr {
			collectReferencedSequences(v, into)
		}
	case cjson.Object:
		for _, key := range node.Obj.Keys() {
			value, _ := node.Obj.Get(key)
			if isInt(value) && strings.HasSuffix(key, "sequence") {
				into[value.Int] = true
			}
			collectReferencedSequences(value, into)
		}
	}
}

// checkSigilSign is the documents.json / signatures.json / links.json
// section of verify_bundle. The blocks are informational-but-verifiable:
// every stated fact is cross-checked against the events themselves and a
// contradiction fails the bundle; fields this verifier does not know,
// including any claim about legal effect or validity, are ignored and can
// never influence the verdict.
func (r *run) checkSigilSign(b bundle.Reader) *hardError {
	var present []string
	for _, name := range []string{"documents.json", "signatures.json", "links.json"} {
		if b.IsFile(name) {
			present = append(present, name)
		}
	}
	if len(present) == 0 {
		return nil
	}

	// A second streaming pass over the events, keeping only those the
	// blocks reference or that carry a signing: resource.
	wanted := map[int64]bool{}
	for _, name := range present {
		doc, herr := decodeOptional(b, name)
		if herr != nil {
			return herr
		}
		collectReferencedSequences(doc, wanted)
	}

	eventBySequence := map[int64]*cjson.Value{}
	eventsBySigningResource := map[string][]*cjson.Value{}
	if b.IsFile("events.ndjson") {
		f, err := b.Open("events.ndjson")
		if err != nil {
			return err.(*hardError)
		}
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
			resource := event.Field("resource")
			isSigning := isString(resource) && strings.HasPrefix(resource.Str, "signing:")
			if !isSigning {
				key, ok := arrayKey(event.Field("seq"))
				if !ok || !wanted[key] {
					continue
				}
			}
			if seq := event.Field("seq"); isInt(seq) {
				eventBySequence[seq.Int] = event
			}
			if isSigning {
				eventsBySigningResource[resource.Str] = append(eventsBySigningResource[resource.Str], event)
			}
		}
		f.Close()
		if lerr := lines.Err(); lerr != nil {
			if lerr == bundle.ErrLineTooLong {
				return hard(fmt.Sprintf("events.ndjson line %d is longer than the %d bytes this verifier accepts; nothing was verified", lines.Number()+2, bundle.MaxLineBytes), ExitError)
			}
			return hard("could not read [events.ndjson]", 1)
		}
	}

	if b.IsFile("documents.json") {
		r.info("Checking documents.json (document hashes against the chain)...")
		doc, herr := decodeOptional(b, "documents.json")
		if herr != nil {
			return herr
		}
		var records *cjson.Value
		if isObject(doc) {
			records = doc.Field("documents")
		}
		if !isArray(records) {
			r.report(`documents.json is present but malformed - expected a "documents" list`, ResultContent)
		} else {
			checked := 0
			for _, record := range records.Arr {
				slug := "(unnamed)"
				if s := record.Field("slug"); isString(s) {
					slug = s.Str
				}
				for _, version := range arrayCast(record.Field("versions")) {
					sequence := version.Field("published_sequence")
					statedSha := lower(text(version.Field("sha256")))
					if !isInt(sequence) {
						r.report(fmt.Sprintf("documents.json: document %s lists a version without an integer published_sequence", slug), ResultContent)
						continue
					}
					published := eventBySequence[sequence.Int]
					if published == nil {
						r.report(fmt.Sprintf("documents.json: document %s points at sequence %d, which is not in this bundle", slug, sequence.Int), ResultContent)
						continue
					}
					if !strEq(published.Field("action"), "document.published") {
						r.report(fmt.Sprintf("documents.json: document %s points at sequence %d, which is not a document.published event", slug, sequence.Int), ResultContent)
						continue
					}
					if !isObject(published.Field("payload")) {
						r.note(fmt.Sprintf("documents.json: document %s's publication at sequence %d has a redacted payload; the stated hash cannot be cross-checked", slug, sequence.Int))
						continue
					}
					ledgeredSha := lower(text(published.Field("payload").Field("sha256")))
					if ledgeredSha != statedSha {
						r.report(fmt.Sprintf("documents.json: document %s states sha256 %s but its document.published event at sequence %d carries %s", slug, statedSha, sequence.Int, ledgeredSha), ResultContent)
						continue
					}
					checked++
				}
			}
			r.note(fmt.Sprintf("documents.json: %d document version hash(es) match their ledgered document.published events", checked))
		}
	}

	if b.IsFile("signatures.json") {
		r.info("Checking signatures.json (signature records against the chain)...")
		doc, herr := decodeOptional(b, "signatures.json")
		if herr != nil {
			return herr
		}
		var records *cjson.Value
		if isObject(doc) {
			records = doc.Field("signatures")
		}
		if !isArray(records) {
			r.report(`signatures.json is present but malformed - expected a "signatures" list`, ResultContent)
		} else {
			checked := 0
			for _, record := range records.Arr {
				id := record.Field("id")
				if !isString(id) {
					r.report("signatures.json contains a record without an id", ResultContent)
					continue
				}
				label := "signatures.json: signing " + id.Str
				documentSha := ""
				if d := record.Field("document"); isObject(d) {
					documentSha = lower(text(d.Field("sha256")))
				}
				signingEvents := eventsBySigningResource["signing:"+id.Str]
				if len(signingEvents) == 0 {
					r.report(fmt.Sprintf("%s has no events in this bundle - a stated signing must exist in the chain", label), ResultContent)
					continue
				}

				// The chain's own story: what each signer saw and signed.
				viewedShaByEmail := map[string]string{}
				signedByEmail := map[string]*cjson.Value{}
				var signedOrder []string
				for _, ev := range signingEvents {
					payload := ev.Field("payload")
					if !isObject(payload) {
						continue // redacted: declared destruction, noted globally
					}
					var email string
					if signer := payload.Field("signer"); isObject(signer) && isString(signer.Field("email")) {
						email = lower(signer.Field("email").Str)
					} else {
						continue
					}
					if strEq(ev.Field("action"), "signature.viewed") {
						viewedShaByEmail[email] = lower(text(payload.Field("sha256")))
					}
					if strEq(ev.Field("action"), "signature.signed") {
						if _, seen := signedByEmail[email]; !seen {
							signedOrder = append(signedOrder, email)
						}
						signedByEmail[email] = payload
					}
				}

				for _, email := range signedOrder {
					payload := signedByEmail[email]
					signedSha := lower(text(payload.Field("sha256")))
					if documentSha != "" && signedSha != documentSha {
						r.report(fmt.Sprintf("%s: the record states document sha256 %s but signer %s's signature.signed event carries %s", label, documentSha, email, signedSha), ResultContent)
					}
					if viewed, ok := viewedShaByEmail[email]; ok && viewed != signedSha {
						r.report(fmt.Sprintf("%s: signer %s viewed sha256 %s but signed %s - the viewed and signed versions must be the same", label, email, viewed, signedSha), ResultContent)
					}
				}

				// Every signer the record claims signed must have a
				// matching event, with the mark hash agreeing when stated.
				for _, signer := range arrayCast(record.Field("signers")) {
					if !strEq(signer.Field("status"), "signed") {
						continue
					}
					email := ""
					if e := signer.Field("email"); isString(e) {
						email = lower(e.Str)
					}
					payload := signedByEmail[email]
					if payload == nil {
						r.report(fmt.Sprintf("%s: the record claims %s signed but no signature.signed event in this bundle records it", label, email), ResultContent)
						continue
					}
					statedMark := lower(text(signer.Field("signature_sha256")))
					ledgeredMark := lower(text(payload.Field("signature_sha256")))
					if statedMark != "" && ledgeredMark != "" && ledgeredMark != statedMark {
						r.report(fmt.Sprintf("%s: %s's stated signature-mark hash does not match the ledgered event", label, email), ResultContent)
					}
					checked++
				}
			}
			r.note(fmt.Sprintf("signatures.json: %d signature(s) verified against their ledgered events - viewed and signed hashes agree", checked))
			r.note("signatures.json is informational metadata: its facts are cross-checked against the chain above, and everything else in it - including any claim about legal effect or validity - is ignored and cannot influence the verdict")
		}
	}

	if b.IsFile("links.json") {
		r.info("Checking links.json (document <-> event links against the chain)...")
		doc, herr := decodeOptional(b, "links.json")
		if herr != nil {
			return herr
		}
		var records *cjson.Value
		if isObject(doc) {
			records = doc.Field("links")
		}
		if !isArray(records) {
			r.report(`links.json is present but malformed - expected a "links" list`, ResultContent)
		} else {
			resolvedLinks := 0
			for index, link := range records.Arr {
				linkLabel := fmt.Sprintf("links.json entry #%d", index+1)
				linkSha := lower(text(link.Field("sha256")))
				resolved := true
				for _, pair := range [][2]string{{"linked_sequence", "document.linked"}, {"unlinked_sequence", "document.unlinked"}} {
					field, expectedAction := pair[0], pair[1]
					sequence := link.Field(field)
					if nullish(sequence) {
						if field == "linked_sequence" {
							r.report(fmt.Sprintf("%s has no linked_sequence - a link must point at its ledgered fact", linkLabel), ResultContent)
							resolved = false
						}
						continue
					}
					var linkEvent *cjson.Value
					if isInt(sequence) {
						linkEvent = eventBySequence[sequence.Int]
					}
					if linkEvent == nil || !strEq(linkEvent.Field("action"), expectedAction) {
						r.report(fmt.Sprintf("%s: %s %s does not resolve to a %s event in this bundle", linkLabel, field, text(sequence), expectedAction), ResultContent)
						resolved = false
						continue
					}
					if !isObject(linkEvent.Field("payload")) {
						r.note(fmt.Sprintf("%s: the %s event at sequence %d has a redacted payload; its hash cannot be cross-checked", linkLabel, expectedAction, sequence.Int))
						continue
					}
					eventSha := lower(text(linkEvent.Field("payload").Field("sha256")))
					if linkSha != "" && eventSha != linkSha {
						r.report(fmt.Sprintf("%s: states sha256 %s but the %s event at sequence %d carries %s", linkLabel, linkSha, expectedAction, sequence.Int, eventSha), ResultContent)
						resolved = false
					}
				}
				if resolved {
					resolvedLinks++
				}
			}
			r.note(fmt.Sprintf("links.json: %d link fact(s) resolve to their ledgered document.linked/document.unlinked events with matching hashes", resolvedLinks))
			r.note("a link records that the exporting tenant associated a document with these events at a provable time; it asserts nothing about legal effect, which this verifier neither checks nor reports")
		}
	}
	return nil
}
