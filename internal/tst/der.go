// Package tst reads and validates RFC 3161 timestamp tokens exactly the way
// verify.php does. It is a port of verify.php's hand-written DER reader and
// its anchor_* functions rather than a use of encoding/asn1 or crypto/x509,
// because the two verifiers must accept and reject the same bytes: a token
// or certificate that one parser tolerates and the other refuses would let
// a bundle pass in one verifier and fail in the other, which FORMAT.md
// treats as a soundness bug. Every failure string here is byte-identical
// to the one verify.php reports, so the two failure lists line up.
package tst

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sigilbase/verifier-go/internal/phpcompat"
)

// Element is one DER element as verify.php's der_read returns it: the tag
// class and number, whether it is constructed, its content bytes, and the
// total encoded length including the header.
type Element struct {
	Class       int
	Constructed bool
	Number      int
	Content     []byte
	Total       int
}

// Read mirrors der_read. Tag number 31 (the multi-byte tag form) is not
// supported, the length must be short form or long form of one to four
// bytes, and indefinite lengths are refused. A long-form length with
// leading zero bytes is accepted, as verify.php accepts it, even though
// DER would forbid it; Reencode later writes it minimally.
func Read(der []byte, offset int) (Element, error) {
	available := len(der) - offset

	if available < 2 {
		return Element{}, errors.New("truncated DER element")
	}

	first := int(der[offset])
	number := first & 0x1F

	if number == 0x1F {
		return Element{}, errors.New("unsupported DER tag form")
	}

	lengthByte := int(der[offset+1])
	headerLength := 2
	contentLength := 0

	if lengthByte < 0x80 {
		contentLength = lengthByte
	} else {
		lengthOfLength := lengthByte & 0x7F

		if lengthOfLength == 0 || lengthOfLength > 4 || available < 2+lengthOfLength {
			return Element{}, errors.New("unsupported or truncated DER length")
		}

		for i := 0; i < lengthOfLength; i++ {
			contentLength = contentLength<<8 | int(der[offset+2+i])
		}

		headerLength += lengthOfLength
	}

	if available < headerLength+contentLength {
		return Element{}, errors.New("truncated DER content")
	}

	return Element{
		Class:       first >> 6,
		Constructed: first&0x20 != 0,
		Number:      number,
		Content:     der[offset+headerLength : offset+headerLength+contentLength],
		Total:       headerLength + contentLength,
	}, nil
}

// Children mirrors der_children: every element in content, back to back,
// with any read error propagated.
func Children(content []byte) ([]Element, error) {
	var children []Element
	offset := 0

	for offset < len(content) {
		child, err := Read(content, offset)
		if err != nil {
			return nil, err
		}

		children = append(children, child)
		offset += child.Total
	}

	return children, nil
}

// Reencode mirrors der_reencode: the element's header written with a
// minimal length, followed by its content unchanged.
func Reencode(e Element) []byte {
	tag := byte(e.Class<<6) | byte(e.Number)
	if e.Constructed {
		tag |= 0x20
	}

	length := len(e.Content)

	if length < 0x80 {
		out := make([]byte, 0, 2+length)
		out = append(out, tag, byte(length))
		return append(out, e.Content...)
	}

	var lengthBytes []byte
	for length > 0 {
		lengthBytes = append([]byte{byte(length & 0xFF)}, lengthBytes...)
		length >>= 8
	}

	out := make([]byte, 0, 2+len(lengthBytes)+len(e.Content))
	out = append(out, tag, 0x80|byte(len(lengthBytes)))
	out = append(out, lengthBytes...)
	return append(out, e.Content...)
}

// ReencodeDeep re-encodes an element and, when it is constructed and its
// content parses as a sequence of elements, each of those recursively, all
// with minimal lengths. This is what OpenSSL's i2d produces after d2i has
// read a structure with tolerant lengths, and it is the input over which
// X509_verify hashes a certificate's tbsCertificate. A constructed element
// whose content does not parse is copied as it stands.
func ReencodeDeep(e Element) []byte {
	if e.Constructed {
		children, err := Children(e.Content)
		if err == nil {
			var content []byte
			for _, child := range children {
				content = append(content, ReencodeDeep(child)...)
			}

			return Reencode(Element{Class: e.Class, Constructed: true, Number: e.Number, Content: content})
		}
	}

	return Reencode(e)
}

// DecodeOID mirrors der_decode_oid, including what it does not check: arcs
// accumulate in a 64-bit integer that wraps as PHP's does, and a trailing
// incomplete arc is dropped silently.
func DecodeOID(content []byte) (string, error) {
	if len(content) == 0 {
		return "", errors.New("empty OID")
	}

	first := int64(content[0])
	var arcs []string

	switch {
	case first < 40:
		arcs = []string{"0", strconv.FormatInt(first, 10)}
	case first < 80:
		arcs = []string{"1", strconv.FormatInt(first-40, 10)}
	default:
		arcs = []string{"2", strconv.FormatInt(first-80, 10)}
	}

	var value uint64

	for i := 1; i < len(content); i++ {
		b := content[i]
		value = value<<7 | uint64(b&0x7F)

		if b&0x80 == 0 {
			arcs = append(arcs, strconv.FormatInt(int64(value), 10))
			value = 0
		}
	}

	return strings.Join(arcs, "."), nil
}

// generalizedTime mirrors der_decode_generalized_time.
func generalizedTime(content []byte) (int64, error) {
	t, ok := phpcompat.GeneralizedTime(string(content))
	if !ok {
		return 0, fmt.Errorf("unsupported GeneralizedTime [%s]", content)
	}

	return t, nil
}

// decodeTime mirrors der_decode_time: an X.509 Time is either a
// GeneralizedTime or a UTCTime (RFC 5280 section 4.1.2.5); anything else
// is an unsupported encoding.
func decodeTime(e Element) (int64, error) {
	if e.Class == 0 && e.Number == 0x18 {
		return generalizedTime(e.Content)
	}

	if e.Class != 0 || e.Number != 0x17 {
		return 0, errors.New("unsupported X.509 Time encoding")
	}

	t, ok := phpcompat.UTCTime(string(e.Content))
	if !ok {
		return 0, errors.New("unsupported X.509 Time encoding")
	}

	return t, nil
}
