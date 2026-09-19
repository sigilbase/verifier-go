package cjson

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// FuzzParse holds the parser to three promises on arbitrary bytes: it never
// panics, anything it accepts either canonicalises or fails only for the
// two number reasons, and a canonical encoding is a fixed point (it parses
// again and canonicalises to the same bytes).
func FuzzParse(f *testing.F) {
	bs := "\\" // a JSON backslash, kept out of the source as a literal escape
	seeds := []string{
		`{"action":"user.login","actor":"user:2","payload":{"n":1},"seq":1,"v":1}`,
		`[1,2,3]`, `{}`, `[]`, `null`, `"x"`, `-0`, `1e400`, `9223372036854775808`,
		`{"a":"` + bs + `ud834` + bs + `udd1e"}`, `{"a":"` + bs + `ud800"}`, "{\"a\":\"\xff\"}",
		`{"` + bs + `u0000a":1}`, "{\"\xef\xac\x81\":1,\"\xf0\x9f\x98\x80\":2,\"\xe2\x82\xac\":3}",
		strings.Repeat("[", 511) + strings.Repeat("]", 511),
		strings.Repeat("[", 512) + strings.Repeat("]", 512), `{"a":1,"a":2}`,
		`{"a":"` + bs + `u0000` + bs + `u001f` + bs + `b` + bs + `f` + bs + `n` + bs + `r` + bs + `t` + bs + `"` + bs + bs + bs + `/"}`,
		"\xEF\xBB\xBF{}", `{"a":1} x`, "",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Parse(data)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("error is not a ParseError: %v", err)
			}
			return
		}
		out, err := Canonical(v)
		if err != nil {
			if !errors.Is(err, ErrFloat) && !errors.Is(err, ErrIntRange) {
				t.Fatalf("unexpected canonical error: %v", err)
			}
			return
		}
		again, err := Parse(out)
		if err != nil {
			t.Fatalf("canonical output does not parse: %v (%q)", err, out)
		}
		out2, err := Canonical(again)
		if err != nil {
			t.Fatalf("canonical output does not canonicalise: %v", err)
		}
		if !bytes.Equal(out, out2) {
			t.Fatalf("canonical form is not a fixed point:\n%q\n%q", out, out2)
		}
	})
}
