package tst

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
)

// The cryptographic primitives verify.php reaches through ext-openssl,
// reproduced over hand-parsed structures. OpenSSL's own policies are kept
// where they decide acceptance: RSA_verify's limits on the modulus and
// exponent, the PKCS#1 v1.5 DigestInfo that must match exactly, the
// X509_verify requirement that the outer and inner signature algorithms
// agree, and a signature BIT STRING with no unused bits.

// hashFunc is one digest OpenSSL can be asked for, with the DigestInfo
// prefix PKCS#1 v1.5 wraps it in.
type hashFunc struct {
	name   string
	size   int
	sum    func([]byte) []byte
	prefix []byte
}

var (
	hashMD5    = &hashFunc{"md5", 16, func(b []byte) []byte { s := md5.Sum(b); return s[:] }, []byte{0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10}}
	hashSHA1   = &hashFunc{"sha1", 20, func(b []byte) []byte { s := sha1.Sum(b); return s[:] }, []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}}
	hashSHA224 = &hashFunc{"sha224", 28, func(b []byte) []byte { s := sha256.Sum224(b); return s[:] }, []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}}
	hashSHA256 = &hashFunc{"sha256", 32, func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }, []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}}
	hashSHA384 = &hashFunc{"sha384", 48, func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }, []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}}
	hashSHA512 = &hashFunc{"sha512", 64, func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }, []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}}
)

// Digest algorithm identifiers as they appear in AlgorithmIdentifiers.
var digestOIDs = map[string]*hashFunc{
	"1.2.840.113549.2.5":     hashMD5,
	"1.3.14.3.2.26":          hashSHA1,
	"2.16.840.1.101.3.4.2.4": hashSHA224,
	"2.16.840.1.101.3.4.2.1": hashSHA256,
	"2.16.840.1.101.3.4.2.2": hashSHA384,
	"2.16.840.1.101.3.4.2.3": hashSHA512,
}

const (
	oidRSAEncryption = "1.2.840.113549.1.1.1"
	oidRSASSAPSS     = "1.2.840.113549.1.1.10"
	oidMGF1          = "1.2.840.113549.1.1.8"
	oidECPublicKey   = "1.2.840.10045.2.1"
	oidEd25519       = "1.3.101.112"

	oidP224 = "1.3.132.0.33"
	oidP256 = "1.2.840.10045.3.1.7"
	oidP384 = "1.3.132.0.34"
	oidP521 = "1.3.132.0.35"
)

// Signature algorithms X509_verify is given for chain links, mapped to the
// key family and digest they imply.
var rsaPKCS1SignatureOIDs = map[string]*hashFunc{
	"1.2.840.113549.1.1.4":  hashMD5,
	"1.2.840.113549.1.1.5":  hashSHA1,
	"1.2.840.113549.1.1.14": hashSHA224,
	"1.2.840.113549.1.1.11": hashSHA256,
	"1.2.840.113549.1.1.12": hashSHA384,
	"1.2.840.113549.1.1.13": hashSHA512,
}

var ecdsaSignatureOIDs = map[string]*hashFunc{
	"1.2.840.10045.4.1":   hashSHA1,
	"1.2.840.10045.4.3.1": hashSHA224,
	"1.2.840.10045.4.3.2": hashSHA256,
	"1.2.840.10045.4.3.3": hashSHA384,
	"1.2.840.10045.4.3.4": hashSHA512,
}

// publicKey is a parsed SubjectPublicKeyInfo of one of the families the
// verifier can check signatures with.
type publicKey struct {
	kind string // "rsa", "ec", "ed25519"
	n, e *big.Int
	ec   *ecdsa.PublicKey
	ed   ed25519.PublicKey
}

// parsedCertificate is the whole Certificate SEQUENCE: tbsCertificate,
// signatureAlgorithm and signatureValue, plus the tbs fields.
type parsedCertificate struct {
	tbs       Element
	fields    []Element
	base      int
	sigAlg    Element
	signature Element
}

func parseCertificate(der []byte) (*parsedCertificate, error) {
	certificate, err := Read(der, 0)
	if err != nil {
		return nil, err
	}

	children, err := Children(certificate.Content)
	if err != nil {
		return nil, err
	}

	if len(children) < 3 {
		return nil, errors.New("certificate is malformed")
	}

	fields, err := Children(children[0].Content)
	if err != nil {
		return nil, err
	}

	base := 0
	if len(fields) > 0 && fields[0].Class == 2 {
		base = 1
	}

	if len(fields) < base+6 {
		return nil, errors.New("tbsCertificate is malformed")
	}

	return &parsedCertificate{tbs: children[0], fields: fields, base: base, sigAlg: children[1], signature: children[2]}, nil
}

// derInteger reads an INTEGER the way OpenSSL's decoder does: non-empty,
// non-negative for the uses here, and without the illegal padding of a
// leading zero byte before a byte whose top bit is clear.
func derInteger(e Element) (*big.Int, error) {
	if e.Number != 0x02 || len(e.Content) == 0 {
		return nil, errors.New("not an INTEGER")
	}

	if e.Content[0]&0x80 != 0 {
		return nil, errors.New("negative INTEGER")
	}

	if len(e.Content) > 1 && e.Content[0] == 0 && e.Content[1]&0x80 == 0 {
		return nil, errors.New("INTEGER with illegal padding")
	}

	return new(big.Int).SetBytes(e.Content), nil
}

// parseSPKI reads SubjectPublicKeyInfo ::= SEQUENCE { algorithm
// AlgorithmIdentifier, subjectPublicKey BIT STRING } for the RSA, EC and
// Ed25519 families. Anything else is a key the verifier cannot check with,
// which verify.php reports as a signature that does not verify.
func parseSPKI(spki Element) (*publicKey, error) {
	fields, err := Children(spki.Content)
	if err != nil {
		return nil, err
	}

	if len(fields) < 2 || fields[1].Number != 0x03 || len(fields[1].Content) < 1 {
		return nil, errors.New("SubjectPublicKeyInfo is malformed")
	}

	algorithm, err := Children(fields[0].Content)
	if err != nil {
		return nil, err
	}

	if len(algorithm) == 0 {
		return nil, errors.New("SubjectPublicKeyInfo is malformed")
	}

	oid, err := DecodeOID(algorithm[0].Content)
	if err != nil {
		return nil, err
	}

	keyBytes := fields[1].Content[1:]

	switch oid {
	case oidRSAEncryption, oidRSASSAPSS:
		sequence, err := Read(keyBytes, 0)
		if err != nil {
			return nil, err
		}

		integers, err := Children(sequence.Content)
		if err != nil {
			return nil, err
		}

		if len(integers) < 2 {
			return nil, errors.New("RSAPublicKey is malformed")
		}

		n, err := derInteger(integers[0])
		if err != nil {
			return nil, err
		}

		e, err := derInteger(integers[1])
		if err != nil {
			return nil, err
		}

		return &publicKey{kind: "rsa", n: n, e: e}, nil

	case oidECPublicKey:
		if len(algorithm) < 2 || algorithm[1].Number != 0x06 {
			return nil, errors.New("EC key has no named curve")
		}

		curveOID, err := DecodeOID(algorithm[1].Content)
		if err != nil {
			return nil, err
		}

		var curve elliptic.Curve

		switch curveOID {
		case oidP224:
			curve = elliptic.P224()
		case oidP256:
			curve = elliptic.P256()
		case oidP384:
			curve = elliptic.P384()
		case oidP521:
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported EC curve")
		}

		key, err := ecdsa.ParseUncompressedPublicKey(curve, keyBytes)
		if err != nil {
			return nil, err
		}

		return &publicKey{kind: "ec", ec: key}, nil

	case oidEd25519:
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, errors.New("Ed25519 key is not 32 bytes")
		}

		return &publicKey{kind: "ed25519", ed: ed25519.PublicKey(append([]byte{}, keyBytes...))}, nil
	}

	return nil, errors.New("unsupported public key algorithm")
}

// rsaPublicOperation is RSA_public_decrypt with no padding, under
// RSA_verify's acceptance rules: the signature is exactly the modulus
// length, the modulus is at most 16384 bits, the exponent is smaller than
// the modulus and (for moduli above 3072 bits) at most 64 bits wide, and
// the signature value is below the modulus.
func rsaPublicOperation(n, e *big.Int, signature []byte) ([]byte, bool) {
	if n.Sign() <= 0 || e.Sign() <= 0 || n.BitLen() > 16384 || n.Cmp(e) <= 0 {
		return nil, false
	}

	if n.BitLen() > 3072 && e.BitLen() > 64 {
		return nil, false
	}

	k := (n.BitLen() + 7) / 8

	if len(signature) != k {
		return nil, false
	}

	s := new(big.Int).SetBytes(signature)

	if s.Cmp(n) >= 0 {
		return nil, false
	}

	return new(big.Int).Exp(s, e, n).FillBytes(make([]byte, k)), true
}

// verifyRSAPKCS1v15 is RSA_verify: the recovered block must be exactly
// 0x00 0x01, at least eight 0xFF bytes, 0x00, then the DigestInfo with a
// NULL parameter and the digest of the data.
func verifyRSAPKCS1v15(n, e *big.Int, h *hashFunc, data, signature []byte) bool {
	em, ok := rsaPublicOperation(n, e, signature)
	if !ok {
		return false
	}

	t := append(append([]byte{}, h.prefix...), h.sum(data)...)
	k := len(em)

	if k < len(t)+11 {
		return false
	}

	expected := make([]byte, k)
	expected[1] = 0x01

	for i := 2; i < k-len(t)-1; i++ {
		expected[i] = 0xFF
	}

	copy(expected[k-len(t):], t)

	return bytes.Equal(em, expected)
}

// pssParams are the RSASSA-PSS-params OpenSSL reads from a signature
// algorithm identifier. Only MGF1 with the same digest as the hash is
// supported; a mismatch fails verification.
type pssParams struct {
	hash       *hashFunc
	saltLength int64
}

func parsePSSParams(algorithm Element) (*pssParams, bool) {
	fields, err := Children(algorithm.Content)
	if err != nil || len(fields) == 0 {
		return nil, false
	}

	params := &pssParams{hash: hashSHA1, saltLength: 20}

	if len(fields) < 2 {
		return params, true
	}

	options, err := Children(fields[1].Content)
	if err != nil {
		return nil, false
	}

	mgfHash := hashSHA1

	for _, option := range options {
		if option.Class != 2 {
			return nil, false
		}

		inner, err := Children(option.Content)
		if err != nil || len(inner) == 0 {
			return nil, false
		}

		switch option.Number {
		case 0:
			h, ok := digestFromAlgorithm(inner[0])
			if !ok {
				return nil, false
			}

			params.hash = h
		case 1:
			mgf, err := Children(inner[0].Content)
			if err != nil || len(mgf) < 2 {
				return nil, false
			}

			oid, err := DecodeOID(mgf[0].Content)
			if err != nil || oid != oidMGF1 {
				return nil, false
			}

			h, ok := digestFromAlgorithm(mgf[1])
			if !ok {
				return nil, false
			}

			mgfHash = h
		case 2:
			value, err := derInteger(inner[0])
			if err != nil || value.BitLen() > 31 {
				return nil, false
			}

			params.saltLength = value.Int64()
		case 3:
			value, err := derInteger(inner[0])
			if err != nil || value.Cmp(big.NewInt(1)) != 0 {
				return nil, false
			}
		default:
			return nil, false
		}
	}

	if mgfHash != params.hash {
		return nil, false
	}

	return params, true
}

func digestFromAlgorithm(algorithm Element) (*hashFunc, bool) {
	fields, err := Children(algorithm.Content)
	if err != nil || len(fields) == 0 {
		return nil, false
	}

	oid, err := DecodeOID(fields[0].Content)
	if err != nil {
		return nil, false
	}

	h, ok := digestOIDs[oid]

	return h, ok && h != nil
}

// verifyRSAPSS is RSA_verify_PKCS1_PSS_mgf1 with the salt length the
// parameters state (RFC 8017 section 9.1.2).
func verifyRSAPSS(n, e *big.Int, params *pssParams, data, signature []byte) bool {
	em, ok := rsaPublicOperation(n, e, signature)
	if !ok {
		return false
	}

	h := params.hash
	emBits := n.BitLen() - 1
	emLen := (emBits + 7) / 8

	for len(em) > emLen {
		if em[0] != 0 {
			return false
		}

		em = em[1:]
	}

	hLen := h.size
	saltLen := int(params.saltLength)

	if saltLen < 0 || emLen < hLen+saltLen+2 || em[emLen-1] != 0xBC {
		return false
	}

	maskedDB := em[:emLen-hLen-1]
	hash := em[emLen-hLen-1 : emLen-1]
	topBits := 8*emLen - emBits

	if topBits > 0 && maskedDB[0]>>(8-topBits) != 0 {
		return false
	}

	db := make([]byte, len(maskedDB))
	copy(db, maskedDB)
	mgf1XOR(db, hash, h)

	if topBits > 0 {
		db[0] &= 0xFF >> topBits
	}

	psLen := emLen - hLen - saltLen - 2

	for i := 0; i < psLen; i++ {
		if db[i] != 0 {
			return false
		}
	}

	if db[psLen] != 0x01 {
		return false
	}

	salt := db[psLen+1:]
	mPrime := make([]byte, 0, 8+hLen+saltLen)
	mPrime = append(mPrime, make([]byte, 8)...)
	mPrime = append(mPrime, h.sum(data)...)
	mPrime = append(mPrime, salt...)

	return bytes.Equal(hash, h.sum(mPrime))
}

// mgf1XOR applies MGF1 (RFC 8017 appendix B.2.1) with seed to out in place.
func mgf1XOR(out, seed []byte, h *hashFunc) {
	var counter [4]byte
	done := 0

	for done < len(out) {
		block := h.sum(append(append([]byte{}, seed...), counter[:]...))

		for i := 0; i < len(block) && done < len(out); i++ {
			out[done] ^= block[i]
			done++
		}

		for i := 3; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}
}

// verifyWithDigest is openssl_verify($data, $signature, $key, OPENSSL_ALGO_*):
// the key's own family decides the scheme and the requested digest is
// applied to it. OpenSSL refuses a digest-based verification with an
// Ed25519 key, so that family fails here.
func verifyWithDigest(key *publicKey, h *hashFunc, data, signature []byte) bool {
	switch key.kind {
	case "rsa":
		return verifyRSAPKCS1v15(key.n, key.e, h, data, signature)
	case "ec":
		return ecdsa.VerifyASN1(key.ec, h.sum(data), signature)
	}

	return false
}

// certificateSignatureValid is openssl_x509_verify($certificate, $issuerKey),
// which is X509_verify: the outer signatureAlgorithm must equal the
// tbsCertificate's signature field, the signature BIT STRING must have no
// unused bits, and the signature must verify over the re-encoded
// tbsCertificate with the scheme the algorithm names and a key of the
// family it requires.
func certificateSignatureValid(certificateDER []byte, issuerKey *publicKey) bool {
	certificate, err := parseCertificate(certificateDER)
	if err != nil {
		return false
	}

	inner := certificate.fields[certificate.base+1]

	if !bytes.Equal(ReencodeDeep(inner), ReencodeDeep(certificate.sigAlg)) {
		return false
	}

	if certificate.signature.Number != 0x03 || len(certificate.signature.Content) < 1 || certificate.signature.Content[0] != 0 {
		return false
	}

	signature := certificate.signature.Content[1:]

	algorithm, err := Children(certificate.sigAlg.Content)
	if err != nil || len(algorithm) == 0 {
		return false
	}

	oid, err := DecodeOID(algorithm[0].Content)
	if err != nil {
		return false
	}

	tbs := ReencodeDeep(certificate.tbs)

	if h, ok := rsaPKCS1SignatureOIDs[oid]; ok {
		return issuerKey.kind == "rsa" && verifyRSAPKCS1v15(issuerKey.n, issuerKey.e, h, tbs, signature)
	}

	if h, ok := ecdsaSignatureOIDs[oid]; ok {
		return issuerKey.kind == "ec" && ecdsa.VerifyASN1(issuerKey.ec, h.sum(tbs), signature)
	}

	switch oid {
	case oidRSASSAPSS:
		if issuerKey.kind != "rsa" {
			return false
		}

		params, ok := parsePSSParams(certificate.sigAlg)
		if !ok {
			return false
		}

		return verifyRSAPSS(issuerKey.n, issuerKey.e, params, tbs, signature)

	case oidEd25519:
		return issuerKey.kind == "ed25519" && len(signature) == ed25519.SignatureSize && ed25519.Verify(issuerKey.ed, tbs, signature)
	}

	return false
}

// certificatePublicKey is openssl_pkey_get_public on a certificate: the
// key inside its SubjectPublicKeyInfo.
func certificatePublicKey(certificateDER []byte) (*publicKey, error) {
	certificate, err := parseCertificate(certificateDER)
	if err != nil {
		return nil, err
	}

	return parseSPKI(certificate.fields[certificate.base+5])
}
