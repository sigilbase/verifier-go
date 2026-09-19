package tst

import (
	"bytes"
	"crypto/sha1"
	"fmt"
)

// imprintDigests are the digests verify.php accepts for the message
// imprint, the messageDigest attribute and the CMS signature.
var imprintDigests = map[string]*hashFunc{
	"2.16.840.1.101.3.4.2.1": hashSHA256,
	"2.16.840.1.101.3.4.2.2": hashSHA384,
	"2.16.840.1.101.3.4.2.3": hashSHA512,
}

// Validate mirrors anchor_validate: the imprint against the message, the
// contentType and messageDigest attributes, the CMS signature under the
// signer certificate embedded in the token, that signer's validity at
// genTime and its timestamping extended key usage, and, when a CA is
// given, the chain from the signer to a self-signed root inside it with
// every issuer held to IssuerProblems. caPEM nil means no CA: the chain is
// not walked, and the caller reports that. The failures come back in
// verify.php's order and wording, and the function returns early exactly
// where verify.php does.
func Validate(token *Token, message []byte, caPEM *string) []string {
	var failures []string

	imprintHash, ok := imprintDigests[token.ImprintAlg]

	if !ok {
		failures = append(failures, fmt.Sprintf("unsupported imprint algorithm [%s]", token.ImprintAlg))
	} else if !bytes.Equal(imprintHash.sum(message), token.Imprint) {
		failures = append(failures, "the token message imprint does not match the checkpoint hash")
	}

	if token.ContentTypeAttr != oidTSTInfo {
		failures = append(failures, "the signed contentType attribute is not id-ct-TSTInfo")
	}

	digest, ok := imprintDigests[token.DigestAlg]

	if !ok {
		return append(failures, fmt.Sprintf("unsupported digest algorithm [%s]", token.DigestAlg))
	}

	if !bytes.Equal(digest.sum(token.TSTInfo), token.MessageDigestAttr) {
		failures = append(failures, "the messageDigest attribute does not match the TSTInfo content")
	}

	// The signer certificate must be embedded (Sigilbase requests certReq).
	var signerCert []byte

	for _, certificateDER := range token.Certs {
		parts, err := ParseCertParts(certificateDER)
		if err != nil {
			continue
		}

		if bytes.Equal(parts.Serial, token.SignerSerial) && bytes.Equal(parts.Issuer, token.SignerIssuer) {
			signerCert = certificateDER

			break
		}
	}

	if signerCert == nil {
		return append(failures, "the signer certificate is not embedded in the token")
	}

	// The digest the signature algorithm implies. verify.php hands OpenSSL
	// only the digest, so the key's own family decides the scheme; an
	// ECDSA identifier over an RSA key verifies as RSA with that digest.
	var algorithm *hashFunc

	switch token.SigAlg {
	case "1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2":
		algorithm = hashSHA256
	case "1.2.840.113549.1.1.12", "1.2.840.10045.4.3.3":
		algorithm = hashSHA384
	case "1.2.840.113549.1.1.13", "1.2.840.10045.4.3.4":
		algorithm = hashSHA512
	case oidRSAEncryption:
		algorithm = digest
	}

	if algorithm == nil {
		return append(failures, fmt.Sprintf("unsupported signature algorithm [%s]", token.SigAlg))
	}

	signerKey, err := certificatePublicKey(signerCert)

	if err != nil || !verifyWithDigest(signerKey, algorithm, token.SignedAttrsSet, token.Signature) {
		failures = append(failures, "the CMS signature over the signed attributes does not verify")
	}

	notBefore, notAfter, extendedKeyUsage, parsed := signerCertificateFacts(signerCert)

	if !parsed {
		failures = append(failures, "the signer certificate does not parse")
	} else {
		if token.GenTime < notBefore || token.GenTime > notAfter {
			failures = append(failures, "the signer certificate was not valid at genTime")
		}

		if !extendedKeyUsage[oidTimeStamping] {
			failures = append(failures, "the signer certificate lacks the timestamping extended key usage")
		}
	}

	if caPEM != nil {
		anchors := PEMCertificates(*caPEM)

		if len(anchors) == 0 {
			return append(failures, "the provided CA chain contains no certificates")
		}

		anchorSet := map[[20]byte]bool{}
		for _, anchor := range anchors {
			anchorSet[sha1.Sum(anchor)] = true
		}

		pool := make([][]byte, 0, len(token.Certs)+len(anchors))
		pool = append(pool, token.Certs...)
		pool = append(pool, anchors...)

		current := signerCert
		seen := map[[20]byte]bool{}

		for depth := 0; depth < 8; depth++ {
			fingerprint := sha1.Sum(current)

			if seen[fingerprint] {
				return append(failures, "the certificate chain loops")
			}

			seen[fingerprint] = true

			parts, err := ParseCertParts(current)
			if err != nil {
				return append(failures, "a certificate in the chain does not parse")
			}

			if bytes.Equal(parts.Issuer, parts.Subject) {
				if !anchorSet[fingerprint] {
					failures = append(failures, "the chain terminates at a root that is not in the provided CA")
				}

				return failures
			}

			var issuer []byte

			for _, candidate := range pool {
				candidateParts, err := ParseCertParts(candidate)
				if err != nil {
					continue
				}

				if bytes.Equal(candidateParts.Subject, parts.Issuer) {
					issuer = candidate

					break
				}
			}

			if issuer == nil {
				return append(failures, "the certificate chain is incomplete: an issuer certificate is missing")
			}

			issuerKey, err := certificatePublicKey(issuer)

			if err != nil || !certificateSignatureValid(current, issuerKey) {
				return append(failures, "a certificate signature in the chain does not verify")
			}

			// Only a CA may issue. depth intermediates already sit between
			// this issuer and the signer.
			if problems := IssuerProblems(issuer, token.GenTime, depth); len(problems) > 0 {
				return append(failures, problems...)
			}

			current = issuer
		}

		failures = append(failures, "the certificate chain is too deep")
	}

	return failures
}

// signerCertificateFacts is what verify.php takes from openssl_x509_parse
// on the signer: the validity bounds and the set of extended key usage
// identifiers. parsed is false where OpenSSL would have returned false,
// which here means the certificate, its validity or its extensions cannot
// be read.
func signerCertificateFacts(certificateDER []byte) (notBefore, notAfter int64, extendedKeyUsage map[string]bool, parsed bool) {
	parts, err := ParseCertParts(certificateDER)
	if err != nil {
		return 0, 0, nil, false
	}

	validity, err := Children(parts.Validity.Content)
	if err != nil || len(validity) < 2 {
		return 0, 0, nil, false
	}

	notBefore, err = decodeTime(validity[0])
	if err != nil {
		return 0, 0, nil, false
	}

	notAfter, err = decodeTime(validity[1])
	if err != nil {
		return 0, 0, nil, false
	}

	extensions, err := certExtensions(parts.Extensions)
	if err != nil {
		return 0, 0, nil, false
	}

	extendedKeyUsage = map[string]bool{}

	// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId. A value
	// OpenSSL cannot print carries no "Time Stamping" text either, so an
	// unreadable extension counts as lacking the usage rather than as a
	// parse failure.
	if value, present := extensions[oidExtendedKeyUse]; present {
		if sequence, err := Read(value, 0); err == nil {
			if purposes, err := Children(sequence.Content); err == nil {
				for _, purpose := range purposes {
					if oid, err := DecodeOID(purpose.Content); err == nil {
						extendedKeyUsage[oid] = true
					}
				}
			}
		}
	}

	return notBefore, notAfter, extendedKeyUsage, true
}
