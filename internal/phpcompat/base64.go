// Package phpcompat reproduces the handful of PHP runtime behaviours that
// verify.php leans on and that Go's standard library does differently:
// strict base64 decoding, the (int) cast, and the way DateTimeImmutable and
// gmmktime read a date. Two verifiers can only agree on hostile input if
// they read the bytes the same way, so each function here mirrors the PHP
// implementation rather than the tidier Go one, and each is pinned by a
// vector in vectors/vectors.json.
package phpcompat

// Base64Strict decodes s the way PHP's base64_decode($s, true) does: the
// standard alphabet, whitespace (space, tab, CR, LF) skipped, any other
// character outside the alphabet rejected, no data after padding, at most
// two padding characters, and padding that must complete a quartet when it
// is present at all. Unpadded input is accepted. The second result is false
// where PHP returns false.
func Base64Strict(s string) ([]byte, bool) {
	const pad = '='
	out := make([]byte, 0, len(s)*3/4)
	var acc uint32
	var bits uint
	count := 0   // alphabet characters consumed
	padding := 0 // padding characters seen

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == pad {
			padding++
			continue
		}
		v, ok := base64Value(ch)
		if !ok {
			if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
				continue
			}
			return nil, false
		}
		if padding > 0 {
			return nil, false
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		count++
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}

	if count%4 == 1 {
		return nil, false
	}
	if padding > 0 && (padding > 2 || (count+padding)%4 != 0) {
		return nil, false
	}
	return out, true
}

func base64Value(ch byte) (byte, bool) {
	switch {
	case ch >= 'A' && ch <= 'Z':
		return ch - 'A', true
	case ch >= 'a' && ch <= 'z':
		return ch - 'a' + 26, true
	case ch >= '0' && ch <= '9':
		return ch - '0' + 52, true
	case ch == '+':
		return 62, true
	case ch == '/':
		return 63, true
	}
	return 0, false
}
