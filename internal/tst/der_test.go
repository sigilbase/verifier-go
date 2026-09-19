package tst

import (
	"bytes"
	"testing"
)

func TestReadAcceptsNonMinimalLengthAndReencodesMinimally(t *testing.T) {
	// SEQUENCE with a two-byte long-form length whose first byte is zero:
	// not DER, but verify.php's der_read accepts it.
	in := []byte{0x30, 0x82, 0x00, 0x03, 0x02, 0x01, 0x05}

	e, err := Read(in, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if e.Class != 0 || !e.Constructed || e.Number != 0x10 || e.Total != 7 || !bytes.Equal(e.Content, []byte{0x02, 0x01, 0x05}) {
		t.Fatalf("unexpected element %+v", e)
	}

	if got := Reencode(e); !bytes.Equal(got, []byte{0x30, 0x03, 0x02, 0x01, 0x05}) {
		t.Fatalf("Reencode = %x", got)
	}

	if got := ReencodeDeep(e); !bytes.Equal(got, []byte{0x30, 0x03, 0x02, 0x01, 0x05}) {
		t.Fatalf("ReencodeDeep = %x", got)
	}
}

func TestReadErrorsMatchPHP(t *testing.T) {
	cases := map[string][]byte{
		"truncated DER element":               {0x30},
		"unsupported DER tag form":            {0x1F, 0x00},
		"unsupported or truncated DER length": {0x30, 0x80},
		"truncated DER content":               {0x30, 0x05, 0x01},
	}

	for want, in := range cases {
		if _, err := Read(in, 0); err == nil || err.Error() != want {
			t.Errorf("Read(%x) error = %v; want %q", in, err, want)
		}
	}

	if _, err := Read([]byte{0x30, 0x85, 0, 0, 0, 0, 0}, 0); err == nil || err.Error() != "unsupported or truncated DER length" {
		t.Errorf("five-byte length: %v", err)
	}

	if _, err := Read([]byte{0x30, 0x82, 0x00}, 0); err == nil || err.Error() != "unsupported or truncated DER length" {
		t.Errorf("short long-form length: %v", err)
	}

	if _, err := Read([]byte{0x30, 0x01, 0x00}, 5); err == nil || err.Error() != "truncated DER element" {
		t.Errorf("offset past end: %v", err)
	}
}

func TestChildrenAndReencodeDeep(t *testing.T) {
	// Outer SEQUENCE with a non-minimal length wrapping an inner SEQUENCE
	// with a non-minimal length: ReencodeDeep fixes both, Reencode only
	// the outer one.
	inner := []byte{0x30, 0x81, 0x03, 0x02, 0x01, 0x07}
	outer := append([]byte{0x30, 0x82, 0x00, byte(len(inner))}, inner...)

	e, err := Read(outer, 0)
	if err != nil {
		t.Fatal(err)
	}

	children, err := Children(e.Content)
	if err != nil || len(children) != 1 || children[0].Total != len(inner) {
		t.Fatalf("Children = %+v, %v", children, err)
	}

	if got := Reencode(e); !bytes.Equal(got, append([]byte{0x30, byte(len(inner))}, inner...)) {
		t.Errorf("Reencode = %x", got)
	}

	if got := ReencodeDeep(e); !bytes.Equal(got, []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x07}) {
		t.Errorf("ReencodeDeep = %x", got)
	}

	if _, err := Children([]byte{0x02, 0x01, 0x07, 0x02}); err == nil {
		t.Errorf("Children accepted a truncated trailing element")
	}
}

func TestReencodeLongForm(t *testing.T) {
	content := make([]byte, 300)
	got := Reencode(Element{Class: 0, Constructed: true, Number: 0x10, Content: content})

	if !bytes.Equal(got[:4], []byte{0x30, 0x82, 0x01, 0x2C}) || len(got) != 304 {
		t.Errorf("Reencode long form header = %x len %d", got[:4], len(got))
	}
}

func TestDecodeOID(t *testing.T) {
	cases := map[string][]byte{
		"1.2.840.113549.1.1.1":   {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01},
		"2.16.840.1.101.3.4.2.1": {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01},
		"1.3.6.1.5.5.7.3.8":      {0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08},
		"0.9":                    {0x09},
		"2.100":                  {0xb4},
		// A trailing incomplete arc is dropped, as der_decode_oid drops it.
		"1.2": {0x2a, 0x86},
	}

	for want, in := range cases {
		got, err := DecodeOID(in)
		if err != nil || got != want {
			t.Errorf("DecodeOID(%x) = %q, %v; want %q", in, got, err, want)
		}
	}

	if _, err := DecodeOID(nil); err == nil || err.Error() != "empty OID" {
		t.Errorf("empty OID: %v", err)
	}
}

func TestDecodeTime(t *testing.T) {
	gen := Element{Class: 0, Number: 0x18, Content: []byte("20260911193134Z")}
	if got, err := decodeTime(gen); err != nil || got != 1789155094 {
		t.Errorf("GeneralizedTime = %d, %v", got, err)
	}

	utc := Element{Class: 0, Number: 0x17, Content: []byte("260911193134Z")}
	if got, err := decodeTime(utc); err != nil || got != 1789155094 {
		t.Errorf("UTCTime = %d, %v", got, err)
	}

	for _, bad := range []Element{
		{Class: 0, Number: 0x17, Content: []byte("2609111931Z")},
		{Class: 0, Number: 0x13, Content: []byte("260911193134Z")},
		{Class: 2, Number: 0x18, Content: []byte("20260911193134Z")},
	} {
		if _, err := decodeTime(bad); err == nil || err.Error() != "unsupported X.509 Time encoding" {
			t.Errorf("decodeTime(%+v) error = %v", bad, err)
		}
	}

	if _, err := decodeTime(Element{Class: 0, Number: 0x18, Content: []byte("2026091119Z")}); err == nil || err.Error() != "unsupported GeneralizedTime [2026091119Z]" {
		t.Errorf("bad GeneralizedTime error = %v", err)
	}
}
