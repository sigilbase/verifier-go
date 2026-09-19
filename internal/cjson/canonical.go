package cjson

import (
	"errors"
	"sort"
	"strconv"
	"unicode/utf8"
)

// ErrFloat is returned when a value holds a non-integer number. Canonical
// JSON for hashing is restricted to integers, so a float has no encoding.
var ErrFloat = errors.New("non-integer numbers cannot be canonicalised")

// ErrIntRange is returned when an integer lies outside +/-(2^53-1), the
// range every JSON reader represents exactly.
var ErrIntRange = errors.New("integer outside the exactly representable range")

const maxExactInt = 9007199254740991

// Canonical returns the RFC 8785 (JCS) encoding of v restricted to
// integers, byte for byte what verify.php's canonical_encode produces:
// object keys sorted by UTF-16 code units, the short escapes for the five
// named control characters, \u00xx with lowercase hex for the rest, and
// every other byte copied as it is.
func Canonical(v *Value) ([]byte, error) {
	out, err := appendCanonical(make([]byte, 0, 256), v)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func appendCanonical(buf []byte, v *Value) ([]byte, error) {
	// A nil value is what an absent field reads as through `?? null`.
	if v == nil {
		return append(buf, "null"...), nil
	}
	switch v.Kind {
	case Null:
		return append(buf, "null"...), nil
	case Bool:
		if v.Bool {
			return append(buf, "true"...), nil
		}
		return append(buf, "false"...), nil
	case Int:
		if v.Int > maxExactInt || v.Int < -maxExactInt {
			return nil, ErrIntRange
		}
		return strconv.AppendInt(buf, v.Int, 10), nil
	case Float:
		return nil, ErrFloat
	case String:
		return appendCanonicalString(buf, v.Str), nil
	case Array:
		buf = append(buf, '[')
		for i, item := range v.Arr {
			if i > 0 {
				buf = append(buf, ',')
			}
			var err error
			buf, err = appendCanonical(buf, item)
			if err != nil {
				return nil, err
			}
		}
		return append(buf, ']'), nil
	case Object:
		return appendCanonicalObject(buf, v.Obj)
	}
	return nil, errors.New("unsupported value kind")
}

const hexDigits = "0123456789abcdef"

func appendCanonicalString(buf []byte, s string) []byte {
	buf = append(buf, '"')
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b == '"':
			buf = append(buf, '\\', '"')
		case b == '\\':
			buf = append(buf, '\\', '\\')
		case b == 0x08:
			buf = append(buf, '\\', 'b')
		case b == 0x09:
			buf = append(buf, '\\', 't')
		case b == 0x0A:
			buf = append(buf, '\\', 'n')
		case b == 0x0C:
			buf = append(buf, '\\', 'f')
		case b == 0x0D:
			buf = append(buf, '\\', 'r')
		case b < 0x20:
			buf = append(buf, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0x0F])
		default:
			buf = append(buf, b)
		}
	}
	return append(buf, '"')
}

func appendCanonicalObject(buf []byte, o *Members) ([]byte, error) {
	n := o.Len()
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool {
		return compareUTF16(o.keys[order[a]], o.keys[order[b]]) < 0
	})
	buf = append(buf, '{')
	for i, idx := range order {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendCanonicalString(buf, o.keys[idx])
		buf = append(buf, ':')
		var err error
		buf, err = appendCanonical(buf, o.vals[idx])
		if err != nil {
			return nil, err
		}
	}
	return append(buf, '}'), nil
}

// unitReader yields the UTF-16 code units of a UTF-8 string one at a time
// without allocating, so key comparison costs nothing beyond the walk.
type unitReader struct {
	s       string
	i       int
	pending uint16
	hasPend bool
}

func (r *unitReader) next() (uint16, bool) {
	if r.hasPend {
		r.hasPend = false
		return r.pending, true
	}
	if r.i >= len(r.s) {
		return 0, false
	}
	c, size := utf8.DecodeRuneInString(r.s[r.i:])
	r.i += size
	if c >= 0x10000 {
		c -= 0x10000
		r.pending = uint16(0xDC00 | (c & 0x3FF))
		r.hasPend = true
		return uint16(0xD800 | (c >> 10)), true
	}
	return uint16(c), true
}

// compareUTF16 orders two keys by their UTF-16 code units, which is the
// order RFC 8785 requires and the one verify.php reproduces with its own
// utf16be() conversion followed by strcmp. It differs from code point order
// exactly where it matters: an astral character (D800..DFFF pairs) sorts
// before U+E000..U+FFFF.
func compareUTF16(a, b string) int {
	ra := unitReader{s: a}
	rb := unitReader{s: b}
	for {
		ua, oka := ra.next()
		ub, okb := rb.next()
		switch {
		case !oka && !okb:
			return 0
		case !oka:
			return -1
		case !okb:
			return 1
		case ua < ub:
			return -1
		case ua > ub:
			return 1
		}
	}
}
