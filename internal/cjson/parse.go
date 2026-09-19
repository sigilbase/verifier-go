package cjson

import (
	"fmt"
	"strconv"
	"unicode/utf8"
)

// ParseError says why a document was rejected. Code is one of "syntax",
// "utf8", "utf16", "ctrl_char", "depth" and "property_name", mirroring the
// json_last_error() classes PHP reports for the same input; Offset is the
// byte position the reader had reached.
type ParseError struct {
	Code   string
	Offset int
	Msg    string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s at offset %d: %s", e.Code, e.Offset, e.Msg)
}

// maxDepth is PHP's default json_decode depth. PHP refuses a container
// whose nesting level, counting the outermost as 1, reaches this value, so
// 511 nested containers decode and 512 do not.
const maxDepth = 512

type parser struct {
	data  []byte
	pos   int
	depth int
	// assoc is json_decode's associative mode, in which an object key may
	// begin with a NUL byte. In object mode PHP cannot create such a
	// property and rejects the document instead.
	assoc bool
}

// Parse decodes exactly one JSON document as PHP's
// json_decode($data, false, 512) would.
func Parse(data []byte) (*Value, error) { return parse(data, false) }

// ParseAssoc decodes as json_decode($data, true, 512) would: identical to
// Parse except that object keys beginning with NUL are allowed.
func ParseAssoc(data []byte) (*Value, error) { return parse(data, true) }

func parse(data []byte, assoc bool) (*Value, error) {
	p := &parser{data: data, assoc: assoc}
	p.skipSpace()
	if p.pos >= len(p.data) {
		return nil, p.fail("syntax", "empty document")
	}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos < len(p.data) {
		return nil, p.unexpected()
	}
	return v, nil
}

func (p *parser) fail(code, msg string) error {
	return &ParseError{Code: code, Offset: p.pos, Msg: msg}
}

// skipSpace skips the only four bytes JSON treats as whitespace. Form feed,
// vertical tab and NUL are control characters to PHP's scanner, and a
// non-breaking space is an ordinary character; neither is skipped.
func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

// unexpected classifies the byte at the cursor the way PHP's scanner does
// outside a string: a control character is a "ctrl_char" error, a byte
// that does not begin well-formed UTF-8 is a "utf8" error, and anything
// else that is not a token is a syntax error.
func (p *parser) unexpected() error {
	if p.pos >= len(p.data) {
		return p.fail("syntax", "unexpected end of input")
	}
	b := p.data[p.pos]
	if b < 0x20 {
		return p.fail("ctrl_char", "control character outside a string")
	}
	if b < 0x80 {
		return p.fail("syntax", fmt.Sprintf("unexpected character %q", b))
	}
	r, size := utf8.DecodeRune(p.data[p.pos:])
	if r == utf8.RuneError && size <= 1 {
		return p.fail("utf8", "malformed UTF-8")
	}
	return p.fail("syntax", fmt.Sprintf("unexpected character %q", r))
}

func (p *parser) value() (*Value, error) {
	if p.pos >= len(p.data) {
		return nil, p.unexpected()
	}
	switch b := p.data[p.pos]; {
	case b == '{':
		return p.object()
	case b == '[':
		return p.array()
	case b == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: String, Str: s}, nil
	case b == 't':
		return p.literal("true", &Value{Kind: Bool, Bool: true})
	case b == 'f':
		return p.literal("false", &Value{Kind: Bool})
	case b == 'n':
		return p.literal("null", &Value{Kind: Null})
	case b == '-' || (b >= '0' && b <= '9'):
		return p.number()
	}
	return nil, p.unexpected()
}

func (p *parser) literal(word string, v *Value) (*Value, error) {
	if len(p.data)-p.pos < len(word) || string(p.data[p.pos:p.pos+len(word)]) != word {
		return nil, p.fail("syntax", "invalid literal")
	}
	p.pos += len(word)
	return v, nil
}

// number reads -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)? and decides,
// with PHP's own rule, whether the result is an int or a float.
func (p *parser) number() (*Value, error) {
	start := p.pos
	negative := false
	if p.data[p.pos] == '-' {
		negative = true
		p.pos++
	}
	if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
		return nil, p.fail("syntax", "malformed number")
	}
	if p.data[p.pos] == '0' {
		p.pos++
	} else {
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	intEnd := p.pos
	isFloat := false
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, p.fail("syntax", "malformed number")
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
		isFloat = true
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, p.fail("syntax", "malformed number")
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
		isFloat = true
	}
	literal := string(p.data[start:p.pos])
	if !isFloat && fitsInt64(literal, negative, intEnd-start) {
		n, err := strconv.ParseInt(literal, 10, 64)
		if err != nil {
			// fitsInt64 already proved the range, so this cannot happen;
			// treat it as PHP would treat an overflow rather than panic.
			return floatValue(literal), nil
		}
		return &Value{Kind: Int, Int: n}, nil
	}
	return floatValue(literal), nil
}

// fitsInt64 is PHP's json scanner rule for choosing int over float: fewer
// than 19 digits always fit; exactly 19 fit when they compare below
// "9223372036854775808", or equal to it and the literal is negative.
func fitsInt64(literal string, negative bool, length int) bool {
	const minDigits = "9223372036854775808"
	digits := length
	if negative {
		digits--
	}
	if digits < len(minDigits) {
		return true
	}
	if digits > len(minDigits) {
		return false
	}
	body := literal
	if negative {
		body = literal[1:]
	}
	switch {
	case body < minDigits:
		return true
	case body == minDigits && negative:
		return true
	}
	return false
}

func floatValue(literal string) *Value {
	// ParseFloat returns +/-Inf with ErrRange on overflow, which is also
	// what PHP's zend_strtod yields for 1e400; the value is kept either way.
	f, _ := strconv.ParseFloat(literal, 64)
	return &Value{Kind: Float, Float: f}
}

// str reads a string starting at the opening quote and returns its decoded
// bytes as a fresh string. The fast path copies a run with no escapes; the
// slow path builds the value byte by byte.
func (p *parser) str() (string, error) {
	p.pos++ // opening quote
	start := p.pos
	for p.pos < len(p.data) {
		b := p.data[p.pos]
		switch {
		case b == '"':
			s := string(p.data[start:p.pos])
			p.pos++
			return s, nil
		case b == '\\':
			buf := make([]byte, 0, (p.pos-start)+16)
			buf = append(buf, p.data[start:p.pos]...)
			return p.strSlow(buf)
		case b < 0x20:
			return "", p.fail("ctrl_char", "control character inside a string")
		case b < 0x80:
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.fail("utf8", "malformed UTF-8 inside a string")
			}
			p.pos += size
		}
	}
	// PHP's scanner meets its end-of-input marker, a NUL, while still inside
	// the string, and reports it as a control character.
	return "", p.fail("ctrl_char", "unterminated string")
}

func (p *parser) strSlow(buf []byte) (string, error) {
	for p.pos < len(p.data) {
		b := p.data[p.pos]
		switch {
		case b == '"':
			p.pos++
			return string(buf), nil
		case b == '\\':
			var err error
			buf, err = p.escape(buf)
			if err != nil {
				return "", err
			}
		case b < 0x20:
			return "", p.fail("ctrl_char", "control character inside a string")
		case b < 0x80:
			buf = append(buf, b)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.fail("utf8", "malformed UTF-8 inside a string")
			}
			buf = append(buf, p.data[p.pos:p.pos+size]...)
			p.pos += size
		}
	}
	return "", p.fail("ctrl_char", "unterminated string")
}

// escape decodes one backslash sequence at the cursor. A \u escape that
// names a high surrogate must be followed immediately by one naming a low
// surrogate; PHP reports any other surrogate escape as a UTF-16 error.
func (p *parser) escape(buf []byte) ([]byte, error) {
	p.pos++ // backslash
	if p.pos >= len(p.data) {
		return nil, p.fail("syntax", "unterminated escape")
	}
	c := p.data[p.pos]
	p.pos++
	switch c {
	case '"', '\\', '/':
		return append(buf, c), nil
	case 'b':
		return append(buf, '\b'), nil
	case 'f':
		return append(buf, '\f'), nil
	case 'n':
		return append(buf, '\n'), nil
	case 'r':
		return append(buf, '\r'), nil
	case 't':
		return append(buf, '\t'), nil
	case 'u':
		unit, ok := p.hex4()
		if !ok {
			return nil, p.fail("syntax", "malformed \\u escape")
		}
		switch {
		case unit >= 0xD800 && unit <= 0xDBFF:
			if len(p.data)-p.pos >= 6 && p.data[p.pos] == '\\' && p.data[p.pos+1] == 'u' {
				save := p.pos
				p.pos += 2
				low, ok := p.hex4()
				if ok && low >= 0xDC00 && low <= 0xDFFF {
					r := rune(0x10000 + (int(unit)-0xD800)<<10 + (int(low) - 0xDC00))
					return utf8.AppendRune(buf, r), nil
				}
				p.pos = save
			}
			return nil, p.fail("utf16", "unpaired UTF-16 surrogate in a \\u escape")
		case unit >= 0xDC00 && unit <= 0xDFFF:
			return nil, p.fail("utf16", "unpaired UTF-16 surrogate in a \\u escape")
		}
		return utf8.AppendRune(buf, rune(unit)), nil
	}
	p.pos--
	return nil, p.fail("syntax", "invalid escape sequence")
}

func (p *parser) hex4() (uint16, bool) {
	if len(p.data)-p.pos < 4 {
		return 0, false
	}
	var v uint16
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		v = v<<4 | uint16(d)
	}
	p.pos += 4
	return v, true
}

func (p *parser) enter() error {
	p.depth++
	if p.depth >= maxDepth {
		return p.fail("depth", "maximum nesting depth exceeded")
	}
	return nil
}

func (p *parser) object() (*Value, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	p.pos++ // {
	obj := NewObject()
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		p.depth--
		return &Value{Kind: Object, Obj: obj}, nil
	}
	for {
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.unexpected()
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.unexpected()
		}
		p.pos++
		p.skipSpace()
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		// PHP creates each member as a property of a stdClass, and a
		// property name cannot begin with NUL, so the pair is refused once
		// it is complete. Associative mode builds an array and has no such
		// limit.
		if !p.assoc && len(key) > 0 && key[0] == 0 {
			return nil, p.fail("property_name", "object key begins with NUL")
		}
		obj.Set(key, val)
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, p.unexpected()
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
			p.skipSpace()
		case '}':
			p.pos++
			p.depth--
			return &Value{Kind: Object, Obj: obj}, nil
		default:
			return nil, p.unexpected()
		}
	}
}

func (p *parser) array() (*Value, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	p.pos++ // [
	var items []*Value
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		p.depth--
		return &Value{Kind: Array, Arr: []*Value{}}, nil
	}
	for {
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		items = append(items, val)
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, p.unexpected()
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
			p.skipSpace()
		case ']':
			p.pos++
			p.depth--
			return &Value{Kind: Array, Arr: items}, nil
		default:
			return nil, p.unexpected()
		}
	}
}
