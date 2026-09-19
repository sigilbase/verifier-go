package cjson

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Every expectation in this file was observed by running json_decode and
// verify.php's canonical_encode under PHP 8.4.25. "ok" means the document
// decodes; an error code names the json_last_error() class PHP reports.
//
// Test inputs write a JSON backslash escape as "~" (so "~u0000" is the JSON
// text backslash-u-0000); esc turns it into the backslash. Spelling the escapes out
// literally would leave the source at the mercy of editors that decode
// them.
func esc(s string) string { return strings.ReplaceAll(s, "~", "\\") }

type verdict struct {
	name  string
	input string
	want  string // "ok" or a ParseError code
}

func parseVerdicts() []verdict {
	nested := func(n int) string {
		return strings.Repeat("[", n) + strings.Repeat("]", n)
	}
	return []verdict{
		{"invalid utf8 raw", "{\"a\":\"\xff\"}", "utf8"},
		{"overlong 2byte", "{\"a\":\"\xc0\xaf\"}", "utf8"},
		{"overlong 3byte", "{\"a\":\"\xe0\x80\xaf\"}", "utf8"},
		{"utf8 encoded surrogate", "{\"a\":\"\xed\xa0\x80\"}", "utf8"},
		{"above U+10FFFF", "{\"a\":\"\xf4\x90\x80\x80\"}", "utf8"},
		{"truncated multibyte", "{\"a\":\"\xe2\x82\"}", "utf8"},
		{"invalid utf8 in key", "{\"\xff\":1}", "utf8"},
		{"invalid utf8 outside string", "{\"a\":1}\xff", "utf8"},
		{"lone high surrogate escape", `{"a":"~ud800"}`, "utf16"},
		{"lone low surrogate escape", `{"a":"~udc00"}`, "utf16"},
		{"high then non-low", `{"a":"~ud800~u0041"}`, "utf16"},
		{"high then malformed escape", `{"a":"~ud800~uZZZZ"}`, "utf16"},
		{"valid pair", `{"a":"~ud834~udd1e"}`, "ok"},
		{"dup keys", `{"a":1,"a":2}`, "ok"},
		{"float", `{"a":1.0}`, "ok"},
		{"exp", `{"a":1e2}`, "ok"},
		{"exp upper plus", `{"a":1E+2}`, "ok"},
		{"neg exp", `{"a":1e-2}`, "ok"},
		{"neg zero", `{"a":-0}`, "ok"},
		{"neg zero float", `{"a":-0.0}`, "ok"},
		{"int64 max+1", `{"a":9223372036854775808}`, "ok"},
		{"huge", `{"a":1e400}`, "ok"},
		{"leading zero", `{"a":01}`, "syntax"},
		{"neg leading zero", `{"a":-01}`, "syntax"},
		{"minus only", `{"a":-}`, "syntax"},
		{"plus", `{"a":+1}`, "syntax"},
		{"dot no int", `{"a":.5}`, "syntax"},
		{"trailing dot", `{"a":1.}`, "syntax"},
		{"exp no digits", `{"a":1e}`, "syntax"},
		{"bom", "\xEF\xBB\xBF{\"a\":1}", "syntax"},
		{"trailing data", `{"a":1} x`, "syntax"},
		{"two docs", `{"a":1}{"a":2}`, "syntax"},
		{"trailing ws", "{\"a\":1} \n\r\t", "ok"},
		{"leading ws", " \t\n\r{\"a\":1}", "ok"},
		{"form feed ws", "\f{\"a\":1}", "ctrl_char"},
		{"vt ws", "\x0b{\"a\":1}", "ctrl_char"},
		{"nul trailing", "{\"a\":1}\x00", "ctrl_char"},
		{"nbsp", "\xc2\xa0{\"a\":1}", "syntax"},
		{"nul key", `{"~u0000a":1}`, "property_name"},
		{"nul in key middle", `{"a~u0000b":1}`, "ok"},
		{"nul key only", `{"~u0000":1}`, "property_name"},
		{"nul key nested", `{"a":{"~u0000b":1}}`, "property_name"},
		{"nul key in array of objects", `[{"~u0000b":1}]`, "property_name"},
		{"empty key", `{"":1}`, "ok"},
		{"nul in value", `{"a":"~u0000"}`, "ok"},
		{"ctrl char raw 0x01", "{\"a\":\"\x01\"}", "ctrl_char"},
		{"ctrl char raw 0x1f", "{\"a\":\"\x1f\"}", "ctrl_char"},
		{"del char raw", "{\"a\":\"\x7f\"}", "ok"},
		{"tab raw", "{\"a\":\"\t\"}", "ctrl_char"},
		{"newline raw", "{\"a\":\"\n\"}", "ctrl_char"},
		{"escape slash", `{"a":"~/"}`, "ok"},
		{"invalid escape", `{"a":"~x"}`, "syntax"},
		{"u escape upper", `{"a":"~u00E9"}`, "ok"},
		{"u escape short", `{"a":"~u00E"}`, "syntax"},
		{"escape of quote", `{"a":"~u0022"}`, "ok"},
		{"escape control", `{"a":"~u001f"}`, "ok"},
		{"escape 0x7f", `{"a":"~u007f"}`, "ok"},
		{"escape 2028", `{"a":"~u2028"}`, "ok"},
		{"depth 511 arrays", nested(511), "ok"},
		{"depth 512 arrays", nested(512), "depth"},
		{"depth 511 in obj", `{"a":` + nested(511) + `}`, "depth"},
		{"depth 510 in obj", `{"a":` + nested(510) + `}`, "ok"},
		{"depth 511 objects", strings.Repeat(`{"a":`, 511) + "1" + strings.Repeat("}", 511), "ok"},
		{"depth 512 objects", strings.Repeat(`{"a":`, 512) + "1" + strings.Repeat("}", 512), "depth"},
		{"top-level int", `1`, "ok"},
		{"top-level string", `"x"`, "ok"},
		{"top-level null", `null`, "ok"},
		{"empty", ``, "syntax"},
		{"ws only", `  `, "syntax"},
		{"numeric key", `{"1":1,"0":2}`, "ok"},
		{"true case", `{"a":True}`, "syntax"},
		{"nan", `{"a":NaN}`, "syntax"},
		{"infinity", `{"a":Infinity}`, "syntax"},
		{"trailing comma obj", `{"a":1,}`, "syntax"},
		{"trailing comma arr", `[1,]`, "syntax"},
		{"single quotes", `{'a':1}`, "syntax"},
		{"comment", `{"a":1}//x`, "syntax"},
		{"unquoted key", `{a:1}`, "syntax"},
		{"empty obj", `{}`, "ok"},
		{"empty arr", `[]`, "ok"},
		{"nested empty", `{"a":{},"b":[]}`, "ok"},
		{"unterminated string", `"abc`, "ctrl_char"},
		{"unterminated object", `{"a":1`, "syntax"},
		{"unterminated array", `[1,2`, "syntax"},
		{"bare comma", `[,1]`, "syntax"},
		{"missing colon", `{"a" 1}`, "syntax"},
		{"missing value", `{"a":}`, "syntax"},
		{"truncated literal", `nul`, "syntax"},
		{"literal with suffix", `truex`, "syntax"},
		{"control after value in array", "[1\x01]", "ctrl_char"},
		{"invalid utf8 after value in array", "[1\xff]", "utf8"},
		{"escape at end of input", `"abc~`, "syntax"},
	}
}

func TestParseVerdictsMatchPHP(t *testing.T) {
	for _, c := range parseVerdicts() {
		input := esc(c.input)
		_, err := Parse([]byte(input))
		got := "ok"
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Errorf("%s: error is not a *ParseError: %v", c.name, err)
				continue
			}
			got = pe.Code
		}
		if got != c.want {
			t.Errorf("%s: Parse(%q) = %s; PHP says %s (err: %v)", c.name, input, got, c.want, err)
		}
	}
}

func TestParseAssocAllowsNulKeys(t *testing.T) {
	v, err := ParseAssoc([]byte(esc(`{"~u0000a":1}`)))
	if err != nil {
		t.Fatalf("ParseAssoc rejected a NUL-leading key: %v", err)
	}
	if m := v.Field("\x00a"); !m.IsInt() || m.Int != 1 {
		t.Errorf("NUL-leading key not stored: %+v", m)
	}
	if _, err := ParseAssoc([]byte(esc(`{"~u0000":1}`))); err != nil {
		t.Errorf("ParseAssoc rejected a NUL-only key: %v", err)
	}
	// Everything else is unchanged in associative mode.
	if _, err := ParseAssoc([]byte(`{"a":`)); err == nil {
		t.Errorf("ParseAssoc accepted a truncated document")
	}
}

func TestNumbersTakePHPsIntOrFloat(t *testing.T) {
	ints := map[string]int64{
		"9223372036854775807":  9223372036854775807,
		"-9223372036854775808": -9223372036854775808,
		"9007199254740992":     9007199254740992,
		"9007199254740991":     9007199254740991,
		"-9007199254740992":    -9007199254740992,
		"-0":                   0,
		"0":                    0,
		"123456789012345678":   123456789012345678,
		"-1":                   -1,
	}
	for in, want := range ints {
		v, err := Parse([]byte(in))
		if err != nil || !v.IsInt() || v.Int != want {
			t.Errorf("Parse(%s) = %+v, %v; want Int %d", in, v, err, want)
		}
	}
	floats := []string{"1.0", "1e2", "1E+2", "1e-2", "-0.0", "9223372036854775808", "-9223372036854775809", "10000000000000000000", "1e400", "12345678901234567890123"}
	for _, in := range floats {
		v, err := Parse([]byte(in))
		if err != nil || v == nil || v.Kind != Float {
			t.Errorf("Parse(%s) = %+v, %v; want Float", in, v, err)
		}
	}
	v, _ := Parse([]byte("1e400"))
	if v.Float <= 1e308 {
		t.Errorf("1e400 should overflow to +Inf, got %v", v.Float)
	}
	v, _ = Parse([]byte("1e2"))
	if v.Float != 100 {
		t.Errorf("1e2 = %v", v.Float)
	}
}

func TestStringsDecode(t *testing.T) {
	cases := map[string]string{
		`"~ud834~udd1e"`:               "\U0001D11E",
		`"~u00E9"`:                     "é",
		`"~u0000"`:                     "\x00",
		`"~/"`:                         "/",
		`"~"~~~b~f~n~r~t"`:             "\"\\\b\f\n\r\t",
		"\"\xc3\xa9\xf0\x9f\x98\x80\"": "\xc3\xa9\xf0\x9f\x98\x80",
		"\"\x7f\"":                     "\x7f",
		`"plain"`:                      "plain",
		`""`:                           "",
		`"~u0041~u0042"`:               "AB",
	}
	for in, want := range cases {
		input := esc(in)
		v, err := Parse([]byte(input))
		if err != nil || !v.IsString() || v.Str != want {
			t.Errorf("Parse(%s) = %+v, %v; want %q", input, v, err, want)
		}
	}
}

func TestParseCopiesInput(t *testing.T) {
	data := []byte(`{"key":"value"}`)
	v, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		data[i] = 'x'
	}
	if v.Field("key") == nil || v.Field("key").Str != "value" {
		t.Errorf("parsed string aliases the input buffer")
	}
}

func TestDuplicateKeysLastValueFirstPosition(t *testing.T) {
	v, err := Parse([]byte(`{"b":1,"a":1,"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if keys := v.Obj.Keys(); len(keys) != 2 || keys[0] != "b" || keys[1] != "a" {
		t.Errorf("keys = %v; want [b a]", keys)
	}
	if b := v.Field("b"); !b.IsInt() || b.Int != 2 {
		t.Errorf("b = %+v; want 2", b)
	}
	if v.Obj.Len() != 2 {
		t.Errorf("Len = %d", v.Obj.Len())
	}
}

func TestObjectGrowsPastLinearScan(t *testing.T) {
	o := NewObject()
	for i := 0; i < 100; i++ {
		o.Set(strings.Repeat("k", i+1), &Value{Kind: Int, Int: int64(i)})
	}
	o.Set("kk", &Value{Kind: Int, Int: -1})
	if o.Len() != 100 {
		t.Errorf("Len = %d", o.Len())
	}
	if v, ok := o.Get("kk"); !ok || v.Int != -1 {
		t.Errorf("replacement lost after index build")
	}
	if v, ok := o.Get(strings.Repeat("k", 100)); !ok || v.Int != 99 {
		t.Errorf("last key not found")
	}
	if _, ok := o.Get("absent"); ok {
		t.Errorf("absent key found")
	}
	if k, v := o.At(1); k != "kk" || v.Int != -1 {
		t.Errorf("At(1) = %s, %+v", k, v)
	}
	o.Set("new-after-index", &Value{Kind: Null})
	if v, ok := o.Get("new-after-index"); !ok || !v.IsNull() {
		t.Errorf("insertion after index build lost")
	}
}

func TestValueHelpersAreNilSafe(t *testing.T) {
	var v *Value
	if !v.IsNull() || v.IsInt() || v.IsString() || v.IsObject() || v.IsArray() {
		t.Errorf("nil value helpers wrong")
	}
	if v.Field("x") != nil || v.Index(0) != nil {
		t.Errorf("nil navigation should yield nil")
	}
	parsed, _ := Parse([]byte(`{"a":[1,"s",null,{"b":true}],"n":null}`))
	if parsed.Field("a").Index(0).Int != 1 || !parsed.Field("a").Index(1).IsString() || !parsed.Field("a").Index(2).IsNull() {
		t.Errorf("navigation wrong")
	}
	if parsed.Field("a").Index(3).Field("b").Kind != Bool {
		t.Errorf("nested object navigation wrong")
	}
	if parsed.Field("a").Index(4) != nil || parsed.Field("a").Index(-1) != nil || parsed.Field("zz") != nil {
		t.Errorf("out of range navigation should yield nil")
	}
	if !parsed.Field("n").IsNull() || !parsed.Field("absent").IsNull() {
		t.Errorf("null detection wrong")
	}
	if !parsed.Field("a").IsArray() || !parsed.IsObject() {
		t.Errorf("kind helpers wrong")
	}
	var nilObj *Members
	if nilObj.Len() != 0 || nilObj.Keys() != nil {
		t.Errorf("nil object helpers wrong")
	}
	if _, ok := nilObj.Get("x"); ok {
		t.Errorf("nil object Get should miss")
	}
}

func canon(t *testing.T, in string) string {
	t.Helper()
	v, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse(%q): %v", in, err)
	}
	out, err := Canonical(v)
	if err != nil {
		t.Fatalf("Canonical(%q): %v", in, err)
	}
	return string(out)
}

func TestCanonicalMatchesVerifyPHP(t *testing.T) {
	// Raw UTF-8 bytes are spelled out so the source stays ASCII.
	const (
		fi        = "\xef\xac\x81"     // U+FB01
		grin      = "\xf0\x9f\x98\x80" // U+1F600
		euro      = "\xe2\x82\xac"     // U+20AC
		eAcute    = "\xc3\xa9"         // U+00E9
		iDiaresis = "\xc3\xaf"         // U+00EF
		u10000    = "\xf0\x90\x80\x80" // U+10000
		u10FFFF   = "\xf4\x8f\xbf\xbf" // U+10FFFF
		uE000     = "\xee\x80\x80"     // U+E000
		uFFFF     = "\xef\xbf\xbf"     // U+FFFF
		u2028     = "\xe2\x80\xa8"     // U+2028
	)
	cases := map[string]string{
		`{"` + fi + `":1,"` + grin + `":2,"` + euro + `":3}`:                                                           `{"` + euro + `":3,"` + grin + `":2,"` + fi + `":1}`,
		`{"~ud800~udc00":1,"~uffff":2,"z":4,"Z":5,"":6,"a":7,"aa":8,"ab":9,"~u00e9":10,"~ue000":11,"~udbff~udfff":12}`: `{"":6,"Z":5,"a":7,"aa":8,"ab":9,"z":4,"` + eAcute + `":10,"` + u10000 + `":1,"` + u10FFFF + `":12,"` + uE000 + `":11,"` + uFFFF + `":2}`,
		`{"b":[1,true,null],"a":"x"}`: `{"a":"x","b":[1,true,null]}`,
		`{"amount":1250,"currency":"GBP","note":"a ~"quoted~" value, ` + eAcute + `"}`: `{"amount":1250,"currency":"GBP","note":"a ~"quoted~" value, ` + eAcute + `"}`,
		`{"tab":"a~tb","quote":"say ~"hi~"","unicode":"na` + iDiaresis + `ve"}`:        `{"quote":"say ~"hi~"","tab":"a~tb","unicode":"na` + iDiaresis + `ve"}`,
		`{"outer":{"inner":[1,2]},"z":true}`:                                           `{"outer":{"inner":[1,2]},"z":true}`,
		`{"a":"~u0000"}`:                                                               `{"a":"~u0000"}`,
		`{"a":"~u001f"}`:                                                               `{"a":"~u001f"}`,
		`{"a":"~u007f"}`:                                                               "{\"a\":\"\x7f\"}",
		`{"a":"~u2028"}`:                                                               `{"a":"` + u2028 + `"}`,
		`{"a":"~/"}`:                                                                   `{"a":"/"}`,
		`{"1":1,"0":2}`:                                                                `{"0":2,"1":1}`,
		`{"a":1,"a":2}`:                                                                `{"a":2}`,
		`{"b":1,"a":1,"b":2}`:                                                          `{"a":1,"b":2}`,
		`{"a":"~b~f~n~r~t~"~~"}`:                                                       `{"a":"~b~f~n~r~t~"~~"}`,
		`{"a":"~u0001~u000b~u000e"}`:                                                   `{"a":"~u0001~u000b~u000e"}`,
		`{"a":"~u0008~u0009~u000a~u000c~u000d"}`:                                       `{"a":"~b~t~n~f~r"}`,
		`{"a":"~u00E9~u0041"}`:                                                         `{"a":"` + eAcute + `A"}`,
		`{}`:                                                                           `{}`,
		`[]`:                                                                           `[]`,
		`{"a":{},"b":[]}`:                                                              `{"a":{},"b":[]}`,
		`[1,2,3]`:                                                                      `[1,2,3]`,
		`null`:                                                                         `null`,
		`"x"`:                                                                          `"x"`,
		`-0`:                                                                           `0`,
		`{"a":9007199254740991,"b":-9007199254740991}`:   `{"a":9007199254740991,"b":-9007199254740991}`,
		`{" 1":"e","-0":"c","01":"b","1":"a","1.5":"d"}`: `{" 1":"e","-0":"c","01":"b","1":"a","1.5":"d"}`,
		`{"a":"` + eAcute + grin + `"}`:                  `{"a":"` + eAcute + grin + `"}`,
		`  {"a" : [ 1 , 2 ] }  `:                         `{"a":[1,2]}`,
	}
	for in, want := range cases {
		input, expected := esc(in), esc(want)
		if got := canon(t, input); got != expected {
			t.Errorf("Canonical(%s)\n got %s\nwant %s", input, got, expected)
		}
	}
}

func TestCanonicalVectorHash(t *testing.T) {
	// The vector spells the accented letter as e plus U+0301 (combining
	// acute), bytes 65 cc 81, and the hash is over exactly those bytes.
	out := canon(t, esc(`{"amount":1250,"currency":"GBP","note":"a ~"quoted~" value, e`+"\xcc\x81"+`"}`))
	sum := sha256.Sum256([]byte(out))
	if got := hex.EncodeToString(sum[:]); got != "949b3ea2c16b0107cac58f400e23b802a8e16ab372bc6c86d8632519f31e260d" {
		t.Errorf("sha256 = %s", got)
	}
}

func TestCanonicalRejectsFloatsAndWideIntegers(t *testing.T) {
	floats := []string{`{"a":1.0}`, `{"a":1e2}`, `{"a":-0.0}`, `{"a":9223372036854775808}`, `{"a":1e400}`, `{"a":{"b":1.5}}`, `[1,[2,[3.5]]]`}
	for _, in := range floats {
		v, err := Parse([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Canonical(v); !errors.Is(err, ErrFloat) {
			t.Errorf("Canonical(%s) err = %v; want ErrFloat", in, err)
		}
	}
	wide := []string{`{"a":9007199254740992}`, `{"a":-9007199254740992}`, `{"a":9223372036854775807}`, `{"a":{"b":9223372036854775807}}`, `[-9223372036854775808]`}
	for _, in := range wide {
		v, err := Parse([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Canonical(v); !errors.Is(err, ErrIntRange) {
			t.Errorf("Canonical(%s) err = %v; want ErrIntRange", in, err)
		}
	}
}

func TestCanonicalOfNilIsNull(t *testing.T) {
	out, err := Canonical(nil)
	if err != nil || string(out) != "null" {
		t.Errorf("Canonical(nil) = %q, %v", out, err)
	}
}

func TestCanonicalOfBuiltValues(t *testing.T) {
	// verify.php builds hash preimages from an ordered PHP array; a caller
	// here builds them with Set, and the sort makes the order irrelevant.
	o := NewObject()
	o.Set("v", &Value{Kind: Int, Int: 1})
	o.Set("stream", &Value{Kind: String, Str: "s"})
	o.Set("seq", &Value{Kind: Int, Int: 7})
	o.Set("prev", nil)
	out, err := Canonical(&Value{Kind: Object, Obj: o})
	if err != nil || string(out) != `{"prev":null,"seq":7,"stream":"s","v":1}` {
		t.Errorf("Canonical = %s, %v", out, err)
	}
	if _, err := Canonical(&Value{Kind: Kind(99)}); err == nil {
		t.Errorf("unknown kind should fail")
	}
}

func TestCompareUTF16(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0}, {"", "a", -1}, {"a", "", 1}, {"a", "a", 0}, {"a", "aa", -1}, {"aa", "a", 1},
		{"Z", "a", -1}, {"z", "é", -1}, {"é", "\U00010000", -1}, {"\U00010000", "\U0010FFFF", -1},
		{"\U0010FFFF", "", -1}, {"", "￿", -1}, {"￿", "\U00010000", 1},
		{"€", "\U0001F600", -1}, {"\U0001F600", "ﬁ", -1},
	}
	for _, c := range cases {
		if got := compareUTF16(c.a, c.b); got != c.want {
			t.Errorf("compareUTF16(%q, %q) = %d; want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseErrorMessage(t *testing.T) {
	_, err := Parse([]byte("{\"a\":1}\xff"))
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Code != "utf8" || pe.Offset != 7 || !strings.Contains(err.Error(), "utf8 at offset 7") {
		t.Errorf("unexpected error %v", err)
	}
}

func TestKindNames(t *testing.T) {
	names := map[Kind]string{Null: "null", Bool: "bool", Int: "int", Float: "float", String: "string", Array: "array", Object: "object", Kind(99): "unknown"}
	for k, want := range names {
		if k.String() != want {
			t.Errorf("%d.String() = %s; want %s", k, k.String(), want)
		}
	}
}

func BenchmarkParseEventLine(b *testing.B) {
	line := []byte(`{"action":"user.login","actor":"user:2","entry_hash":"a33eed80a1c6153ef85ec8f142cbb345f6016b33bc573d6e035cc9be711d7c35","occurred_at":"2026-01-02T03:04:05.000000Z","payload":{"n":1},"payload_hash":"2bfd14f43d17fc7cea24e0917a8879b4b2f880b8baeec1b9d90fbaad655e71bd","payload_state":"present","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","received_at":"2026-01-02T03:04:05.000000Z","resource":null,"seq":1,"v":1}`)
	b.SetBytes(int64(len(line)))
	for i := 0; i < b.N; i++ {
		v, err := Parse(line)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := Canonical(v); err != nil {
			b.Fatal(err)
		}
	}
}
