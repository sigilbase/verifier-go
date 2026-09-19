// Package cjson is the strict JSON reader the verifier uses for every byte
// of bundle content, and the RFC 8785 canonicaliser behind every hash
// preimage.
//
// Its acceptance rules are not the tidy ones of encoding/json but the ones
// PHP's json_decode($text, false, 512) applies, because verify.php reads
// bundles that way and two verifiers can only agree on hostile input if they
// read the bytes identically. encoding/json would silently replace invalid
// UTF-8, accept a lone surrogate escape and turn every number into a float;
// each of those would let one verifier hash a line the other rejects. Every
// rule in this package is pinned by a test whose expectation was observed
// under PHP 8.4.
package cjson

// Kind says which JSON value a Value holds.
type Kind uint8

const (
	Null Kind = iota
	Bool
	// Int is an integer literal that fitted a signed 64-bit integer, which
	// is exactly when PHP produces an int.
	Int
	// Float is what PHP produces for a literal with a fraction or exponent,
	// and for an integer literal outside the signed 64-bit range.
	Float
	String
	Array
	Object
)

// String names the kind for messages.
func (k Kind) String() string {
	switch k {
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
	return "unknown"
}

// Value is one decoded JSON value. Only the field matching Kind is
// meaningful.
type Value struct {
	Kind  Kind
	Bool  bool
	Int   int64
	Float float64
	Str   string
	Arr   []*Value
	Obj   *Members
}

// IsNull reports whether v is JSON null. A nil *Value counts as null,
// because verify.php reads every absent field through `?? null`.
func (v *Value) IsNull() bool { return v == nil || v.Kind == Null }

// IsInt reports whether v is an integer that fitted int64 (PHP's is_int).
func (v *Value) IsInt() bool { return v != nil && v.Kind == Int }

// IsString reports whether v is a string (PHP's is_string).
func (v *Value) IsString() bool { return v != nil && v.Kind == String }

// IsObject reports whether v is an object (PHP's is_object / stdClass).
func (v *Value) IsObject() bool { return v != nil && v.Kind == Object }

// IsArray reports whether v is an array (PHP's is_array on a decoded list).
func (v *Value) IsArray() bool { return v != nil && v.Kind == Array }

// Field returns the member named key when v is an object holding it, and
// nil otherwise: the shape of PHP's `$value->key ?? null`.
func (v *Value) Field(key string) *Value {
	if v == nil || v.Kind != Object || v.Obj == nil {
		return nil
	}
	m, ok := v.Obj.Get(key)
	if !ok {
		return nil
	}
	return m
}

// Index returns element i when v is an array long enough, and nil
// otherwise.
func (v *Value) Index(i int) *Value {
	if v == nil || v.Kind != Array || i < 0 || i >= len(v.Arr) {
		return nil
	}
	return v.Arr[i]
}

// Members is the insertion-ordered member list of a JSON object; the type
// is not called Object because that name is the Kind. A duplicate key
// replaces the value in place, keeping the position of the first
// occurrence, which is what PHP does when json_decode assigns the same
// property twice: the last value wins and the property keeps its slot.
type Members struct {
	keys []string
	vals []*Value
	// idx is built only once an object outgrows a linear scan; most bundle
	// objects have a dozen members and a map per object would cost more
	// than it saves across a million events.
	idx map[string]int
}

const smallObject = 16

// NewObject returns an empty object.
func NewObject() *Members { return &Members{} }

func (o *Members) find(key string) (int, bool) {
	if o == nil {
		return 0, false
	}
	if o.idx != nil {
		i, ok := o.idx[key]
		return i, ok
	}
	for i, k := range o.keys {
		if k == key {
			return i, true
		}
	}
	return 0, false
}

// Get returns the member named key.
func (o *Members) Get(key string) (*Value, bool) {
	i, ok := o.find(key)
	if !ok {
		return nil, false
	}
	return o.vals[i], true
}

// Keys returns the member names in insertion order.
func (o *Members) Keys() []string {
	if o == nil {
		return nil
	}
	out := make([]string, len(o.keys))
	copy(out, o.keys)
	return out
}

// Len returns the number of members.
func (o *Members) Len() int {
	if o == nil {
		return 0
	}
	return len(o.keys)
}

// At returns the i-th member in insertion order.
func (o *Members) At(i int) (string, *Value) {
	return o.keys[i], o.vals[i]
}

// Set adds a member, or replaces the value of an existing one in place.
func (o *Members) Set(key string, v *Value) {
	if i, ok := o.find(key); ok {
		o.vals[i] = v
		return
	}
	o.keys = append(o.keys, key)
	o.vals = append(o.vals, v)
	if o.idx != nil {
		o.idx[key] = len(o.keys) - 1
	} else if len(o.keys) > smallObject {
		o.idx = make(map[string]int, len(o.keys)*2)
		for i, k := range o.keys {
			o.idx[k] = i
		}
	}
}

// Delete removes a member, keeping the order of the rest. It is used by
// the mutation tooling to compare documents with unverified fields
// removed; the verifier itself never deletes.
func (o *Members) Delete(key string) {
	i, ok := o.find(key)
	if !ok {
		return
	}
	o.keys = append(o.keys[:i], o.keys[i+1:]...)
	o.vals = append(o.vals[:i], o.vals[i+1:]...)
	if o.idx != nil {
		o.idx = make(map[string]int, len(o.keys)*2)
		for j, k := range o.keys {
			o.idx[k] = j
		}
	}
}
