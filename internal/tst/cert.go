package tst

import (
	"bytes"
	"errors"
	"math"
	"regexp"

	"github.com/sigilbase/verifier-go/internal/phpcompat"
)

// CertParts is what verify.php's anchor_cert_parts keeps of a certificate's
// tbsCertificate: the serial with leading zero bytes trimmed, the issuer and
// subject re-encoded so they compare bytewise, and the validity and
// extensions elements left raw for the issuer checks to decode.
type CertParts struct {
	Serial     []byte
	Issuer     []byte
	Subject    []byte
	Validity   Element
	Extensions *Element
}

const (
	oidBasicConstraints = "2.5.29.19"
	oidKeyUsage         = "2.5.29.15"
)

// ParseCertParts mirrors anchor_cert_parts. The optional [0] version shifts
// every field by one; issuerUniqueID [1], subjectUniqueID [2] and
// extensions [3] are context-tagged and follow subjectPublicKeyInfo.
func ParseCertParts(der []byte) (CertParts, error) {
	certificate, err := Read(der, 0)
	if err != nil {
		return CertParts{}, err
	}

	children, err := Children(certificate.Content)
	if err != nil {
		return CertParts{}, err
	}

	if len(children) == 0 {
		return CertParts{}, errors.New("certificate is malformed")
	}

	tbs, err := Children(children[0].Content)
	if err != nil {
		return CertParts{}, err
	}

	base := 0
	if len(tbs) > 0 && tbs[0].Class == 2 {
		base = 1
	}

	if len(tbs) < base+6 {
		return CertParts{}, errors.New("tbsCertificate is malformed")
	}

	var extensions *Element

	for i := base + 6; i < len(tbs); i++ {
		if tbs[i].Class == 2 && tbs[i].Number == 3 {
			optional := tbs[i]
			extensions = &optional
		}
	}

	return CertParts{
		Serial:     bytes.TrimLeft(tbs[base].Content, "\x00"),
		Issuer:     Reencode(tbs[base+2]),
		Subject:    Reencode(tbs[base+4]),
		Validity:   tbs[base+3],
		Extensions: extensions,
	}, nil
}

// certExtensions mirrors anchor_cert_extensions: extnID to extnValue
// content, the last occurrence of a repeated extnID winning as it does in
// a PHP array.
func certExtensions(wrapper *Element) (map[string][]byte, error) {
	if wrapper == nil {
		return map[string][]byte{}, nil
	}

	sequence, err := Read(wrapper.Content, 0)
	if err != nil {
		return nil, err
	}

	list, err := Children(sequence.Content)
	if err != nil {
		return nil, err
	}

	extensions := map[string][]byte{}

	// Extensions ::= SEQUENCE OF Extension { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
	for _, extension := range list {
		fields, err := Children(extension.Content)
		if err != nil {
			return nil, err
		}

		if len(fields) < 2 || fields[0].Number != 0x06 {
			return nil, errors.New("certificate extension is malformed")
		}

		value := fields[len(fields)-1]

		if value.Number != 0x04 {
			return nil, errors.New("certificate extension value is malformed")
		}

		oid, err := DecodeOID(fields[0].Content)
		if err != nil {
			return nil, err
		}

		extensions[oid] = value.Content
	}

	return extensions, nil
}

// IssuerProblems mirrors anchor_issuer_problems, the RFC 5280 section 6.1.4
// rules on a certificate acting as an issuer: valid at genTime, a CA by
// basicConstraints (an absent extension counts as FALSE), permitted to sign
// certificates when a keyUsage extension is present, and with no more
// intermediates beneath it than its pathLenConstraint allows. The problems
// come back in verify.php's order and wording.
func IssuerProblems(issuerDER []byte, genTime int64, intermediatesBelow int) []string {
	parts, err := ParseCertParts(issuerDER)
	if err != nil {
		return []string{"an issuer certificate in the chain does not parse"}
	}

	validity, err := Children(parts.Validity.Content)
	if err != nil || len(validity) < 2 {
		return []string{"an issuer certificate in the chain does not parse"}
	}

	notBefore, err := decodeTime(validity[0])
	if err != nil {
		return []string{"an issuer certificate in the chain does not parse"}
	}

	notAfter, err := decodeTime(validity[1])
	if err != nil {
		return []string{"an issuer certificate in the chain does not parse"}
	}

	extensions, err := certExtensions(parts.Extensions)
	if err != nil {
		return []string{"an issuer certificate in the chain does not parse"}
	}

	var problems []string

	if genTime < notBefore || genTime > notAfter {
		problems = append(problems, "an issuer certificate in the chain was not valid at genTime")
	}

	basicConstraints, present := extensions[oidBasicConstraints]

	if !present {
		problems = append(problems, "an issuer certificate in the chain is not a CA: it carries no basicConstraints extension")
	} else {
		isCA := false
		var pathLength int64 = -1
		hasPathLength := false

		// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }
		malformed := func() []string {
			return append(problems, "an issuer certificate in the chain has a malformed basicConstraints extension")
		}

		sequence, err := Read(basicConstraints, 0)
		if err != nil || sequence.Class != 0 || sequence.Number != 0x10 {
			return malformed()
		}

		fields, err := Children(sequence.Content)
		if err != nil {
			return malformed()
		}

		for _, field := range fields {
			if field.Class != 0 {
				continue
			}

			if field.Number == 0x01 {
				isCA = len(field.Content) == 1 && field.Content[0] != 0x00
			} else if field.Number == 0x02 {
				trimmed := bytes.TrimLeft(field.Content, "\x00")
				hasPathLength = true

				// Anything wider than four octets is beyond any chain this walk accepts.
				if len(trimmed) > 4 {
					pathLength = math.MaxInt64
				} else {
					pathLength = 0
					for _, b := range trimmed {
						pathLength = pathLength<<8 | int64(b)
					}
				}
			}
		}

		if !isCA {
			problems = append(problems, "an issuer certificate in the chain is not a CA: basicConstraints cA is FALSE")
		} else if hasPathLength && int64(intermediatesBelow) > pathLength {
			problems = append(problems, "an issuer certificate in the chain has more intermediates beneath it than its pathLenConstraint allows")
		}
	}

	if keyUsage, present := extensions[oidKeyUsage]; present && !keyUsagePermitsCertSign(keyUsage) {
		problems = append(problems, "an issuer certificate in the chain is not permitted to sign certificates: keyUsage lacks keyCertSign")
	}

	return problems
}

// keyUsagePermitsCertSign mirrors anchor_key_usage_permits_cert_sign.
// KeyUsage ::= BIT STRING; the first content octet counts unused trailing
// bits and keyCertSign is bit 5 (0x04) of the first data octet.
func keyUsagePermitsCertSign(extnValue []byte) bool {
	bitString, err := Read(extnValue, 0)
	if err != nil {
		return false
	}

	return bitString.Class == 0 &&
		bitString.Number == 0x03 &&
		len(bitString.Content) >= 2 &&
		bitString.Content[1]&0x04 != 0
}

var (
	pemBlock = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----`)
	// PCRE's \s without Unicode mode: space, tab, LF, VT, FF, CR.
	pemSpace = regexp.MustCompile("[ \t\n\v\f\r]+")
)

// PEMCertificates mirrors anchor_pem_certificates: every BEGIN/END
// CERTIFICATE block, its body stripped of whitespace and decoded with PHP's
// strict base64, with empty decodes dropped.
func PEMCertificates(pem string) [][]byte {
	var certificates [][]byte

	for _, match := range pemBlock.FindAllStringSubmatch(pem, -1) {
		der, ok := phpcompat.Base64Strict(pemSpace.ReplaceAllString(match[1], ""))

		if ok && len(der) > 0 {
			certificates = append(certificates, der)
		}
	}

	return certificates
}
