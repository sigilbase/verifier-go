package verify

import (
	"math"
	"strconv"
	"strings"

	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/internal/phpcompat"
)

// The helpers in this file give decoded JSON values the exact meaning
// verify.php gives them through PHP's loose operators: the null-coalescing
// "?? null", the (string) and (int) casts, is_int and is_string, strict
// comparison, foreach over a possibly non-iterable value, and array-key
// coercion. Every rule below was either read from the PHP manual or
// observed under PHP 8.4 in this session; the two verifiers must agree on
// hostile input, and hostile input is where these rules decide.

// nullish is PHP's "$x ?? null" being null: the field is absent or null.
func nullish(v *cjson.Value) bool {
	return v == nil || v.Kind == cjson.Null
}

func isInt(v *cjson.Value) bool    { return v != nil && v.Kind == cjson.Int }
func isString(v *cjson.Value) bool { return v != nil && v.Kind == cjson.String }
func isObject(v *cjson.Value) bool { return v != nil && v.Kind == cjson.Object }
func isArray(v *cjson.Value) bool  { return v != nil && v.Kind == cjson.Array }

// strEq is PHP's "$x === 'literal'".
func strEq(v *cjson.Value, s string) bool {
	return isString(v) && v.Str == s
}

// text is the (string) cast verify.php applies to bundle values from
// 1.6.0: scalars convert as PHP converts them (true is "1", false and null
// are ""), and arrays and objects become "" rather than "Array" or a
// fatal error. The casts feed hash comparisons, where no string an array
// or object could produce would ever match a hash, so the verdicts are
// unchanged from 1.5.0 wherever 1.5.0 produced one.
func text(v *cjson.Value) string {
	if v == nil {
		return ""
	}
	switch v.Kind {
	case cjson.Bool:
		if v.Bool {
			return "1"
		}
		return ""
	case cjson.Int:
		return strconv.FormatInt(v.Int, 10)
	case cjson.Float:
		return phpFloatString(v.Float)
	case cjson.String:
		return v.Str
	}
	return ""
}

// textOr is "(string) ($x ?? $default)".
func textOr(v *cjson.Value, def string) string {
	if nullish(v) {
		return def
	}
	return text(v)
}

// phpFloatString approximates PHP's float to string conversion (precision
// 14, shortest form, exponent written as E+NN with at least one fractional
// digit). It only ever feeds messages and hash comparisons that cannot
// match, so an exact reproduction of every corner is not needed.
func phpFloatString(f float64) string {
	if math.IsNaN(f) {
		return "NAN"
	}
	if math.IsInf(f, 1) {
		return "INF"
	}
	if math.IsInf(f, -1) {
		return "-INF"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0"
		}
		return "0"
	}
	s := strconv.FormatFloat(f, 'G', 14, 64)
	if i := strings.IndexByte(s, 'E'); i >= 0 {
		mantissa, exp := s[:i], s[i+1:]
		if !strings.Contains(mantissa, ".") {
			mantissa += ".0"
		}
		sign := "+"
		if exp[0] == '-' || exp[0] == '+' {
			if exp[0] == '-' {
				sign = "-"
			}
			exp = exp[1:]
		}
		exp = strings.TrimLeft(exp, "0")
		if exp == "" {
			exp = "0"
		}
		return mantissa + "E" + sign + exp
	}
	return s
}

// intCast is PHP's (int) cast of a decoded value.
func intCast(v *cjson.Value) int64 {
	if v == nil {
		return 0
	}
	switch v.Kind {
	case cjson.Bool:
		if v.Bool {
			return 1
		}
		return 0
	case cjson.Int:
		return v.Int
	case cjson.Float:
		return phpcompat.FloatToInt(v.Float)
	case cjson.String:
		return phpcompat.StringToInt(v.Str)
	case cjson.Array:
		if len(v.Arr) > 0 {
			return 1
		}
		return 0
	case cjson.Object:
		return 1
	}
	return 0
}

// strictEqual is PHP's "===" between two decoded values: null equals
// null, scalars must match in type and value, arrays must match element
// by element, and two objects are never identical because they are
// different instances.
func strictEqual(a, b *cjson.Value) bool {
	if nullish(a) || nullish(b) {
		return nullish(a) && nullish(b)
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case cjson.Bool:
		return a.Bool == b.Bool
	case cjson.Int:
		return a.Int == b.Int
	case cjson.Float:
		return a.Float == b.Float
	case cjson.String:
		return a.Str == b.Str
	case cjson.Array:
		if len(a.Arr) != len(b.Arr) {
			return false
		}
		for i := range a.Arr {
			if !strictEqual(a.Arr[i], b.Arr[i]) {
				return false
			}
		}
		return true
	}
	return false
}

// iterValues is "foreach ($x ?? [] as $value)": the elements of an array,
// the property values of an object, and nothing for anything else (PHP
// warns and skips a scalar).
func iterValues(v *cjson.Value) []*cjson.Value {
	if v == nil {
		return nil
	}
	switch v.Kind {
	case cjson.Array:
		return v.Arr
	case cjson.Object:
		out := make([]*cjson.Value, 0, v.Obj.Len())
		for _, k := range v.Obj.Keys() {
			val, _ := v.Obj.Get(k)
			out = append(out, val)
		}
		return out
	}
	return nil
}

// arrayCast is "(array) ($x ?? [])": null and absent give nothing, an
// array its elements, an object its property values, and a scalar a
// single-element list holding it.
func arrayCast(v *cjson.Value) []*cjson.Value {
	if nullish(v) {
		return nil
	}
	if v.Kind == cjson.Array || v.Kind == cjson.Object {
		return iterValues(v)
	}
	return []*cjson.Value{v}
}

// arrayKey is the integer key PHP would use when a decoded value indexes
// an array: an int as it is, a canonical decimal string as its number, a
// float truncated, a bool as 0 or 1. Null, other strings, arrays and
// objects never reach an integer key.
func arrayKey(v *cjson.Value) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch v.Kind {
	case cjson.Int:
		return v.Int, true
	case cjson.Bool:
		if v.Bool {
			return 1, true
		}
		return 0, true
	case cjson.Float:
		if math.IsNaN(v.Float) || math.IsInf(v.Float, 0) {
			return 0, false
		}
		return phpcompat.FloatToInt(v.Float), true
	case cjson.String:
		s := v.Str
		if s == "" || s == "-" || (len(s) > 1 && s[0] == '0') || (len(s) > 2 && s[0] == '-' && s[1] == '0') || s == "-0" {
			return 0, false
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, false
		}
		for i, c := range s {
			if !(c >= '0' && c <= '9') && !(i == 0 && c == '-') {
				return 0, false
			}
		}
		return n, true
	}
	return 0, false
}

// lower is PHP 8's strtolower: ASCII letters only. strings.ToLower would
// also fold non-ASCII letters, which matters where the verifier compares
// email addresses.
func lower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// hexBytes is PHP's hex2bin: an even number of hexadecimal digits in
// either case, the empty string included. The second result is false
// where PHP returns false.
func hexBytes(s string) ([]byte, bool) {
	if len(s)%2 != 0 {
		return nil, false
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexNibble(s[i])
		lo, ok2 := hexNibble(s[i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out[i/2] = hi<<4 | lo
	}
	return out, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// isHex64 is "strlen($s) === 64 && ctype_xdigit($s)".
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if _, ok := hexNibble(s[i]); !ok {
			return false
		}
	}
	return true
}

// jsonForMessage renders a value for a human-readable message, roughly as
// PHP's json_encode would.
func jsonForMessage(v *cjson.Value) string {
	if v == nil {
		return "null"
	}
	if v.Kind == cjson.Float {
		return phpFloatString(v.Float)
	}
	if out, err := cjson.Canonical(v); err == nil {
		return string(out)
	}
	return text(v)
}
