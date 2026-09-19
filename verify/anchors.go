package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/sigilbase/verifier-go/internal/bundle"
	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/internal/phpcompat"
	"github.com/sigilbase/verifier-go/internal/tst"
)

// checkAnchors is the anchors.json section of verify_bundle: RFC 3161
// tokens over checkpoint hashes, validated against trust roots this
// verifier carries rather than roots the bundle supplied.
func (r *run) checkAnchors(b bundle.Reader, skipAnchors bool, checkpointHashes map[string]bool) *hardError {
	if !b.IsFile("anchors.json") {
		// No anchors at all: nothing was checked, which is not the same as
		// checked and sound.
		r.results.demote(ResultTimestamps, StateNotChecked)
		return nil
	}
	doc, herr := decodeOptional(b, "anchors.json")
	if herr != nil {
		return herr
	}
	var anchors []*cjson.Value
	if isObject(doc) && isArray(doc.Field("anchors")) {
		anchors = doc.Field("anchors").Arr
	}
	switch {
	case len(anchors) > 0 && skipAnchors:
		r.info(fmt.Sprintf("Skipping %d RFC 3161 anchor token(s) (--skip-anchors).", len(anchors)))
		r.results.demote(ResultTimestamps, StateNotChecked)
		return nil
	case len(anchors) == 0:
		r.results.demote(ResultTimestamps, StateNotChecked)
		return nil
	}

	r.info("Checking anchors.json (RFC 3161 timestamps)...")

	for index, anchor := range anchors {
		label := fmt.Sprintf("anchor #%d (%s)", index+1, textOr(anchor.Field("provider"), "unknown"))
		checkpointHash := lower(text(anchor.Field("checkpoint_hash")))

		if !checkpointHashes[checkpointHash] {
			r.report(fmt.Sprintf("%s: anchors a checkpoint hash that is not in this bundle", label), ResultContent)
			continue
		}

		tokenDER, ok := phpcompat.Base64Strict(text(anchor.Field("token")))
		if !ok || len(tokenDER) == 0 {
			r.report(fmt.Sprintf("%s: the token is not valid base64", label), ResultContent)
			continue
		}

		if lower(text(anchor.Field("token_hash"))) != sha256Hex(tokenDER) {
			r.report(fmt.Sprintf("%s: the token does not match its recorded token_hash", label), ResultContent)
			continue
		}

		token, err := tst.ParseToken(tokenDER)
		if err != nil {
			r.report(fmt.Sprintf("%s: the token does not parse (%s)", label, err.Error()), ResultContent)
			continue
		}

		// Trust roots come from this verifier, never from the bundle alone.
		var bundlePEM, trustedPEM, caPEM *string
		if ca := anchor.Field("ca_pem"); isString(ca) && ca.Str != "" {
			s := ca.Str
			bundlePEM = &s
		}
		if trustedPEMPresent(r.tsaRoots) {
			s := r.tsaRoots
			trustedPEM = &s
		}
		caPEM = trustedPEM
		if caPEM == nil {
			caPEM = bundlePEM
		}

		message, _ := hexBytes(checkpointHash)
		for _, problem := range tst.Validate(token, message, caPEM) {
			r.report(fmt.Sprintf("%s: %s", label, problem), ResultTimestamps)
		}

		if trustedPEM == nil && bundlePEM != nil {
			r.unconfirmed(fmt.Sprintf("%s: the token and its imprint verify, and the signer chains only to a root this bundle supplied - which shows the bundle is self-consistent, not that a timestamp authority you trust issued it. Pass --tsa-roots with the authority's own roots to settle it", label), ResultTimestamps)
		} else if caPEM == nil {
			r.unconfirmed(fmt.Sprintf("%s: the token and its imprint verify, but no trust roots were available, so the timestamp authority's identity was not established", label), ResultTimestamps)
		}

		// Informational qualified-TSA metadata (format 1.3): reported and
		// kept out of the verdict.
		if q := anchor.Field("qualified"); q != nil && q.Kind == cjson.Bool && q.Bool {
			providerName := textOr(anchor.Field("provider"), "unknown")
			if pn := anchor.Field("provider_name"); isString(pn) {
				providerName = pn.Str
			}
			jurisdiction := ""
			if j := anchor.Field("jurisdiction"); isString(j) {
				jurisdiction = " (" + j.Str + ")"
			}
			r.note(fmt.Sprintf("%s: the exporter recorded this token as issued by a qualified trust service provider - %s%s. Informational: the verdict rests on the cryptographic checks alone", label, providerName, jurisdiction))
		}
	}
	return nil
}

// checkCertificates is the certificates/ section of verify_bundle:
// Certificates of Evidence are documents about the evidence, checked only
// for presence and hash against the manifest.
func (r *run) checkCertificates(b bundle.Reader, manifest *cjson.Value) *hardError {
	var records []*cjson.Value
	if c := manifest.Field("certificates"); isArray(c) {
		records = c.Arr
	}
	if len(records) == 0 {
		return nil
	}
	r.info(fmt.Sprintf("Checking %d Certificate(s) of Evidence (certificates/)...", len(records)))

	for index, record := range records {
		recordID := fmt.Sprintf("#%d", index+1)
		if id := record.Field("id"); isString(id) {
			recordID = id.Str
		}
		label := "certificate " + recordID

		file := record.Field("file")
		if !isString(file) || !hasPrefix(file.Str, "certificates/") || contains(file.Str, "..") {
			r.report(fmt.Sprintf("%s: the manifest entry has a missing or unsafe file path", label), ResultContent)
			continue
		}
		if !b.IsFile(file.Str) {
			r.report(fmt.Sprintf("%s: listed in the manifest but missing from the bundle", label), ResultContent)
			continue
		}
		f, err := b.Open(file.Str)
		if err != nil {
			return err.(*hardError)
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, f)
		f.Close()
		if copyErr != nil {
			return hard(fmt.Sprintf("could not read [%s]", file.Str), 1)
		}
		if lower(text(record.Field("sha256"))) != hex.EncodeToString(h.Sum(nil)) {
			r.report(fmt.Sprintf("%s: the file does not match its manifest sha256", label), ResultContent)
		}
	}

	r.note(fmt.Sprintf("%d Certificate(s) of Evidence travelled with this bundle. They are documents about the evidence; the cryptographic verification above does not depend on them", len(records)))
	return nil
}

func hasPrefix(s, prefix string) bool { return len(s) >= len(prefix) && s[:len(prefix)] == prefix }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
