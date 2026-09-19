// Package edsig verifies Ed25519 checkpoint signatures under libsodium's
// acceptance rules, which FORMAT.md makes normative because verify.php
// verifies through libsodium.
//
// Go's crypto/ed25519 implements RFC 8032 with a few well-known
// liberties: it accepts a non-canonical public key encoding, a small-order
// public key and a small-order R. libsodium rejects all three before it
// looks at the equation. The differences matter: with a small-order public
// key a signature can be forged without any private key, and the two
// verifiers would then disagree about a bundle. This package reproduces
// libsodium's pre-checks and then defers to crypto/ed25519, which already
// rejects a non-canonical S and compares R by its canonical encoding.
package edsig

import "crypto/ed25519"

// smallOrder is libsodium's blacklist (ge25519_has_small_order): the
// encodings of every point whose order divides 8, with the sign bit of the
// last byte ignored so that each entry covers both x signs.
var smallOrder = [7][32]byte{
	// 0 (order 4)
	{},
	// 1 (order 1)
	{0x01},
	// 2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8)
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	// 55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8)
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	// p-1 (order 2)
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	// p (=0, order 4)
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	// p+1 (=1, order 1)
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// HasSmallOrder reports whether a 32-byte point encoding is one libsodium
// blacklists as small order. The sign bit is ignored, as in libsodium.
func HasSmallOrder(s []byte) bool {
	if len(s) != 32 {
		return false
	}
	for _, b := range smallOrder {
		var c byte
		for i := 0; i < 31; i++ {
			c |= s[i] ^ b[i]
		}
		c |= (s[31] & 0x7f) ^ b[31]
		if c == 0 {
			return true
		}
	}
	return false
}

// IsCanonical reports whether a 32-byte point encoding carries a y
// coordinate below p = 2^255 - 19 (libsodium's ge25519_is_canonical). The
// nineteen encodings with y in [p, 2^255) decode to valid points in most
// libraries, including Go's, and libsodium refuses them.
func IsCanonical(s []byte) bool {
	if len(s) != 32 {
		return false
	}
	// Non-canonical iff bytes 1..30 are all 0xff, the top byte masked of
	// its sign bit is 0x7f, and the low byte is at least 0xed.
	if s[31]&0x7f != 0x7f {
		return true
	}
	for i := 1; i < 31; i++ {
		if s[i] != 0xff {
			return true
		}
	}
	return s[0] < 0xed
}

// Verify reports whether sig is a signature by pub over message that
// libsodium's crypto_sign_verify_detached would accept. Lengths other than
// 32 and 64 bytes are rejected outright, as verify.php rejects them before
// calling libsodium.
func Verify(pub, message, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if HasSmallOrder(sig[:32]) {
		return false
	}
	if !IsCanonical(pub) || HasSmallOrder(pub) {
		return false
	}
	// crypto/ed25519 rejects S >= L, decodes the public key (failing on a
	// y with no matching x), recomputes R and compares its canonical
	// encoding with the signature's first half byte for byte, which is
	// libsodium's remaining behaviour.
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}
