package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/keys"
)

// KeySet is a trusted signing key set in the shape of the /api/v1/keys
// response. Matching is on public key bytes; everything else a bundle
// says about a key is beside the point.
type KeySet struct {
	entries []trustedKey
}

// trustedKey is one entry of the set as verify.php's trusted_key_for sees
// it: the public key, and the window bounds when they are strings.
type trustedKey struct {
	publicKey string
	createdAt *string
	retiredAt *string
}

// EmbeddedKeys is the set compiled into this build from keys/sigilbase.json.
func EmbeddedKeys() *KeySet {
	set, err := parseKeySet(keys.SigilbaseJSON)
	if err != nil {
		// The file is part of the build and a test holds it to shape;
		// an unreadable embed is a broken build, not a runtime condition.
		panic("keys/sigilbase.json: " + err.Error())
	}
	return set
}

// EmbeddedTSARoots is keys/tsa-roots.pem as compiled into this build.
func EmbeddedTSARoots() string {
	return string(keys.TSARootsPEM)
}

// LoadKeyFile reads a --keys file exactly as verify.php's load_key_file
// does. The error message is the one verify.php prints, and the caller
// exits 2.
func LoadKeyFile(path string) (*KeySet, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("--keys file [%s] does not exist", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--keys file [%s] does not exist", path)
	}
	set, perr := parseKeySet(data)
	if perr != nil {
		return nil, fmt.Errorf("--keys file [%s] %s", path, perr.Error())
	}
	return set, nil
}

// parseKeySet decodes a keys document in associative mode (json_decode
// with true), requiring a non-empty "keys" list whose entries are objects
// carrying a string public_key.
func parseKeySet(data []byte) (*KeySet, error) {
	decoded, err := cjson.ParseAssoc(data)
	if err != nil {
		decoded = nil
	}
	var list *cjson.Value
	if decoded != nil && decoded.Kind == cjson.Object {
		list = decoded.Field("keys")
	}
	if !isArray(list) || len(list.Arr) == 0 {
		return nil, fmt.Errorf(`has no "keys" list`)
	}
	set := &KeySet{}
	for _, entry := range list.Arr {
		// In associative mode a JSON object and a JSON array are both PHP
		// arrays, but only an object can carry the string key public_key.
		if !isObject(entry) || !isString(entry.Field("public_key")) {
			return nil, fmt.Errorf("contains an entry without a public_key")
		}
		k := trustedKey{publicKey: entry.Field("public_key").Str}
		if v := entry.Field("created_at"); isString(v) {
			s := v.Str
			k.createdAt = &s
		}
		if v := entry.Field("retired_at"); isString(v) {
			s := v.Str
			k.retiredAt = &s
		}
		set.entries = append(set.entries, k)
	}
	return set, nil
}

// lookup returns the trusted entry for a public key, matched on the key
// bytes (case-insensitively on the hex), or nil (verify.php's
// trusted_key_for).
func (s *KeySet) lookup(publicKeyHex string) *trustedKey {
	want := lower(publicKeyHex)
	for i := range s.entries {
		if lower(s.entries[i].publicKey) == want {
			k := s.entries[i]
			return &k
		}
	}
	return nil
}

// Fingerprints lists the fingerprints of the keys in the set, for the
// human report.
func (s *KeySet) Fingerprints() []string {
	var out []string
	for _, k := range s.entries {
		out = append(out, keyFingerprint(lower(k.publicKey)))
	}
	return out
}

// keyFingerprint is the first 16 hex characters of the SHA-256 of the raw
// public key, or "unreadable" when the hex does not decode
// (verify.php's key_fingerprint). An empty string decodes to no bytes and
// so has a fingerprint, as it does in PHP.
func keyFingerprint(publicKeyHex string) string {
	raw, ok := hexBytes(publicKeyHex)
	if !ok {
		return "unreadable"
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

// keySources is the ordered map of fingerprint to trust source, kept in
// first-insertion order with later assignments overwriting in place, as a
// PHP array does.
type keySources struct {
	order   []string
	sources map[string]string
}

func (k *keySources) set(fingerprint, source string) {
	if k.sources == nil {
		k.sources = map[string]string{}
	}
	if _, seen := k.sources[fingerprint]; !seen {
		k.order = append(k.order, fingerprint)
	}
	k.sources[fingerprint] = source
}

func (k *keySources) list() []KeySource {
	out := make([]KeySource, 0, len(k.order))
	for _, f := range k.order {
		out = append(out, KeySource{Fingerprint: f, Source: k.sources[f]})
	}
	return out
}

// windowProblems mirrors signing_key_window_problems: a trusted key
// vouches only for checkpoints sealed inside its window. createdAt and
// retiredAt are the bounds as the set states them (nil when absent or
// not a string); sealedAt is the checkpoint's created_at as text.
func windowProblems(createdAt, retiredAt *cjson.Value, sealedAtValue string) []string {
	sealedAt, ok := parseRFC3339(sealedAtValue)
	if !ok {
		return []string{fmt.Sprintf("created_at [%s] is not an RFC 3339 timestamp, so the signing key window cannot be checked", sealedAtValue)}
	}
	var problems []string
	if !nullish(createdAt) {
		keyCreatedAt, ok := parseRFC3339Value(createdAt)
		if !ok {
			problems = append(problems, "the manifest's created_at for the signing key is unparseable, so the key window cannot be checked")
		} else if sealedAt.Before(keyCreatedAt) {
			problems = append(problems, fmt.Sprintf("created_at %s is before the signing key was created (%s) - the key had no authority yet", sealedAtValue, text(createdAt)))
		}
	}
	if !nullish(retiredAt) {
		keyRetiredAt, ok := parseRFC3339Value(retiredAt)
		if !ok {
			problems = append(problems, "the manifest's retired_at for the signing key is unparseable, so the key window cannot be checked")
		} else if sealedAt.After(keyRetiredAt) {
			problems = append(problems, fmt.Sprintf("created_at %s is after the signing key's retired_at %s - a retired key signed this checkpoint", sealedAtValue, text(retiredAt)))
		}
	}
	return problems
}

// windowOf turns a trusted entry's string bounds into values for
// windowProblems, so both the trusted set and the manifest go through the
// same rule.
func (k *trustedKey) window() (createdAt, retiredAt *cjson.Value) {
	if k.createdAt != nil {
		createdAt = &cjson.Value{Kind: cjson.String, Str: *k.createdAt}
	}
	if k.retiredAt != nil {
		retiredAt = &cjson.Value{Kind: cjson.String, Str: *k.retiredAt}
	}
	return createdAt, retiredAt
}

// trustedPEMPresent says whether a TSA root string counts as a trusted
// set: verify.php uses it when it is not the empty string.
func trustedPEMPresent(pem string) bool {
	return pem != ""
}

var _ = strings.TrimSpace
