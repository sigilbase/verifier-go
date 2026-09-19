package edsig

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// The vectors in vectors/vectors.json were produced with the published
// corpus test key and checked against libsodium 1.0.22 through PHP's
// sodium_crypto_sign_verify_detached. Each expects "accept" or "reject".
func TestVectorsMatchLibsodium(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Ed25519 struct {
			Cases []struct {
				Name      string `json:"name"`
				PublicKey string `json:"public_key"`
				Message   string `json:"message"`
				Signature string `json:"signature"`
				Expect    string `json:"expect"`
			} `json:"cases"`
		} `json:"ed25519_acceptance"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Ed25519.Cases) < 8 {
		t.Fatalf("expected at least 8 ed25519_acceptance cases, got %d", len(doc.Ed25519.Cases))
	}
	stockAccepted := 0
	for _, c := range doc.Ed25519.Cases {
		pub, _ := hex.DecodeString(c.PublicKey)
		msg, _ := hex.DecodeString(c.Message)
		sig, _ := hex.DecodeString(c.Signature)
		got := Verify(pub, msg, sig)
		want := c.Expect == "accept"
		if got != want {
			t.Errorf("%s: Verify = %v, libsodium says %s", c.Name, got, c.Expect)
		}
		// The point of the pre-checks: the stock verifier accepts several
		// of the rejected cases. If that ever stops being true the vectors
		// still hold, but the reason for this package should be re-read.
		if !want && ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			stockAccepted++
		}
	}
	if stockAccepted == 0 {
		t.Logf("note: crypto/ed25519 now rejects every rejected vector on its own")
	}
}

func TestLengthsAreRejected(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	msg := []byte("m")
	sig := ed25519.Sign(priv, msg)
	if !Verify(pub, msg, sig) {
		t.Fatal("genuine signature rejected")
	}
	if Verify(pub[:31], msg, sig) || Verify(pub, msg, sig[:63]) || Verify(append([]byte{}, pub...)[:0], msg, sig) {
		t.Fatal("wrong lengths accepted")
	}
}

func TestIsCanonical(t *testing.T) {
	p := new(big.Int)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
	for k := int64(-1); k < 19; k++ {
		y := new(big.Int).Add(p, big.NewInt(k))
		enc := littleEndian32(y)
		for _, sign := range []byte{0, 0x80} {
			e := append([]byte{}, enc...)
			e[31] |= sign
			if got, want := IsCanonical(e), k < 0; got != want {
				t.Errorf("IsCanonical(p%+d, sign %02x) = %v, want %v", k, sign, got, want)
			}
		}
	}
	// 2^255 - 20 with the top bit clear is canonical; a random key is canonical.
	if !IsCanonical(make([]byte, 32)) {
		t.Error("zero encoding must be canonical (it is small order, not non-canonical)")
	}
}

// Every blacklisted encoding, with both sign bits, must decode to a point
// of order 1, 2, 4 or 8, and no encoding of the base point or the corpus
// key may be blacklisted. This is checked with independent math/big
// arithmetic on the twisted Edwards curve so the table is not taken on
// trust from libsodium's source.
func TestBlacklistIsExactlySmallOrder(t *testing.T) {
	c := newCurve()
	for i, b := range smallOrder {
		for _, sign := range []byte{0, 0x80} {
			enc := append([]byte{}, b[:]...)
			enc[31] |= sign
			if !HasSmallOrder(enc) {
				t.Errorf("entry %d with sign %02x not detected", i, sign)
			}
			pt, ok := c.decode(enc)
			if !ok {
				// p and p+1 (with sign) decode after reduction; every entry
				// must decode, as libsodium's own frombytes reduces them.
				t.Errorf("entry %d with sign %02x does not decode", i, sign)
				continue
			}
			eight := c.mul(pt, big.NewInt(8))
			if eight.x.Sign() != 0 || eight.y.Cmp(big.NewInt(1)) != 0 {
				t.Errorf("entry %d with sign %02x is not of small order", i, sign)
			}
		}
	}
	base := c.base()
	if HasSmallOrder(c.encode(base)) {
		t.Error("base point flagged as small order")
	}
	corpusKey, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if HasSmallOrder(corpusKey) || !IsCanonical(corpusKey) {
		t.Error("corpus key rejected by the pre-checks")
	}
}

// Minimal affine twisted Edwards arithmetic for the tests above.
type curve struct{ p, d *big.Int }
type point struct{ x, y *big.Int }

func newCurve() *curve {
	p := new(big.Int)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
	d := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), p))
	d.Mod(d, p)
	return &curve{p: p, d: d}
}

func (c *curve) mod(x *big.Int) *big.Int { return new(big.Int).Mod(x, c.p) }

func (c *curve) add(a, b point) point {
	x1y2 := c.mod(new(big.Int).Mul(a.x, b.y))
	x2y1 := c.mod(new(big.Int).Mul(b.x, a.y))
	y1y2 := c.mod(new(big.Int).Mul(a.y, b.y))
	x1x2 := c.mod(new(big.Int).Mul(a.x, b.x))
	k := c.mod(new(big.Int).Mul(c.d, c.mod(new(big.Int).Mul(x1x2, y1y2))))
	den1 := new(big.Int).ModInverse(c.mod(new(big.Int).Add(big.NewInt(1), k)), c.p)
	den2 := new(big.Int).ModInverse(c.mod(new(big.Int).Sub(big.NewInt(1), k)), c.p)
	x3 := c.mod(new(big.Int).Mul(c.mod(new(big.Int).Add(x1y2, x2y1)), den1))
	y3 := c.mod(new(big.Int).Mul(c.mod(new(big.Int).Add(y1y2, x1x2)), den2))
	return point{x3, y3}
}

func (c *curve) mul(a point, s *big.Int) point {
	r := point{big.NewInt(0), big.NewInt(1)}
	q := a
	for i := 0; i < s.BitLen(); i++ {
		if s.Bit(i) == 1 {
			r = c.add(r, q)
		}
		q = c.add(q, q)
	}
	return r
}

func (c *curve) decode(b []byte) (point, bool) {
	rev := make([]byte, 32)
	for i := range rev {
		rev[i] = b[31-i]
	}
	sign := rev[0] >> 7
	rev[0] &= 0x7f
	y := new(big.Int).SetBytes(rev)
	y.Mod(y, c.p) // libsodium's fe25519_frombytes reduces
	y2 := c.mod(new(big.Int).Mul(y, y))
	u := c.mod(new(big.Int).Sub(y2, big.NewInt(1)))
	v := c.mod(new(big.Int).Add(c.mod(new(big.Int).Mul(c.d, y2)), big.NewInt(1)))
	x2 := c.mod(new(big.Int).Mul(u, new(big.Int).ModInverse(v, c.p)))
	x := new(big.Int).ModSqrt(x2, c.p)
	if x == nil {
		return point{}, false
	}
	if x.Bit(0) != uint(sign) {
		x = c.mod(new(big.Int).Neg(x))
	}
	return point{x, y}, true
}

func (c *curve) encode(a point) []byte {
	out := littleEndian32(a.y)
	if a.x.Bit(0) == 1 {
		out[31] |= 0x80
	}
	return out
}

func (c *curve) base() point {
	y := c.mod(new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), c.p)))
	pt, _ := c.decode(littleEndian32(y))
	return pt
}

func littleEndian32(v *big.Int) []byte {
	out := make([]byte, 32)
	b := v.Bytes()
	for i := 0; i < len(b) && i < 32; i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}
