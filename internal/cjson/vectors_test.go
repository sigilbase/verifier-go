package cjson

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// vectors/vectors.json "json_parsing" is PHP's own verdict on each input:
// whether json_decode accepts it, the type it yields, and the canonical
// bytes and hash when the value canonicalises. This parser must match it
// case for case; the file, not this test, is the specification.
func TestJSONParsingVectors(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		JSONParsing struct {
			Cases []struct {
				Name            string `json:"name"`
				InputBase64     string `json:"input_base64"`
				Verdict         string `json:"verdict"`
				Type            string `json:"type"`
				CanonicalBase64 string `json:"canonical_base64"`
				SHA256          string `json:"sha256"`
				CanonicalError  string `json:"canonical_error"`
			} `json:"cases"`
		} `json:"json_parsing"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.JSONParsing.Cases) < 80 {
		t.Fatalf("only %d json_parsing cases", len(doc.JSONParsing.Cases))
	}
	for _, c := range doc.JSONParsing.Cases {
		input, err := base64.StdEncoding.DecodeString(c.InputBase64)
		if err != nil {
			t.Fatal(err)
		}
		v, perr := Parse(input)
		if c.Verdict == "invalid" {
			if perr == nil {
				t.Errorf("%s: parsed, PHP rejects", c.Name)
			}
			continue
		}
		if perr != nil {
			t.Errorf("%s: %v, PHP accepts", c.Name, perr)
			continue
		}
		if got := kindName(v); got != c.Type {
			t.Errorf("%s: type %s, PHP %s", c.Name, got, c.Type)
		}
		canon, cerr := Canonical(v)
		if c.CanonicalError != "" {
			if cerr == nil || cerr.Error() != c.CanonicalError {
				t.Errorf("%s: canonical error %v, PHP %q", c.Name, cerr, c.CanonicalError)
			}
			continue
		}
		if cerr != nil {
			t.Errorf("%s: %v, PHP canonicalises", c.Name, cerr)
			continue
		}
		want, _ := base64.StdEncoding.DecodeString(c.CanonicalBase64)
		if string(canon) != string(want) {
			t.Errorf("%s: canonical %q, PHP %q", c.Name, canon, want)
		}
		sum := sha256.Sum256(canon)
		if hex.EncodeToString(sum[:]) != c.SHA256 {
			t.Errorf("%s: hash differs", c.Name)
		}
	}
}

func kindName(v *Value) string {
	switch v.Kind {
	case Null:
		return "null"
	case Bool:
		return "bool"
	case Int:
		return "int"
	case Float:
		return "float"
	case String:
		return "string"
	case Array:
		return "array"
	case Object:
		return "object"
	}
	return "?"
}

// The canonical_json vectors: value, canonical form and, where given, the
// SHA-256 of the canonical bytes.
func TestCanonicalJSONVectors(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		CanonicalJSON []struct {
			Value     json.RawMessage `json:"value"`
			Canonical string          `json:"canonical"`
			SHA256    string          `json:"sha256"`
		} `json:"canonical_json"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for i, c := range doc.CanonicalJSON {
		v, err := Parse(c.Value)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		canon, err := Canonical(v)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if string(canon) != c.Canonical {
			t.Errorf("vector %d: %q, want %q", i, canon, c.Canonical)
		}
		if c.SHA256 != "" {
			sum := sha256.Sum256(canon)
			if hex.EncodeToString(sum[:]) != c.SHA256 {
				t.Errorf("vector %d: hash differs", i)
			}
		}
	}
	if _, err := Canonical(&Value{Kind: Float, Float: 1}); !errors.Is(err, ErrFloat) {
		t.Error("a float must be ErrFloat")
	}
}
