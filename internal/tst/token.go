package tst

import (
	"bytes"
	"errors"
)

// Token is the part of a DER TimeStampToken that validation needs, as
// verify.php's anchor_parse_token extracts it: the message imprint and its
// algorithm, genTime as a Unix timestamp, the embedded certificates (each
// re-encoded with a minimal outer length), the signer's issuer and serial,
// the signed attributes re-tagged as a SET for the signature input, the
// two mandatory attribute values, the algorithm identifiers, the signature
// bytes and the TSTInfo content the messageDigest attribute covers.
type Token struct {
	ImprintAlg        string
	Imprint           []byte
	GenTime           int64
	Certs             [][]byte
	SignerIssuer      []byte
	SignerSerial      []byte
	SignedAttrsSet    []byte
	ContentTypeAttr   string
	MessageDigestAttr []byte
	DigestAlg         string
	SigAlg            string
	Signature         []byte
	TSTInfo           []byte
}

const (
	oidSignedData     = "1.2.840.113549.1.7.2"
	oidTSTInfo        = "1.2.840.113549.1.9.16.1.4"
	oidContentType    = "1.2.840.113549.1.9.3"
	oidMessageDigest  = "1.2.840.113549.1.9.4"
	oidTimeStamping   = "1.3.6.1.5.5.7.3.8"
	oidExtendedKeyUse = "2.5.29.37"
)

// ParseToken mirrors anchor_parse_token: CMS ContentInfo, SignedData,
// TSTInfo, the certificate set, the first SignerInfo and its signed
// attributes, read far enough to validate and no further. Error messages
// are verify.php's, because the verifier reports them verbatim.
func ParseToken(der []byte) (*Token, error) {
	contentInfo, err := Read(der, 0)
	if err != nil {
		return nil, err
	}

	children, err := Children(contentInfo.Content)
	if err != nil {
		return nil, err
	}

	if len(children) < 2 {
		return nil, errors.New("token is not CMS SignedData")
	}

	oid, err := DecodeOID(children[0].Content)
	if err != nil {
		return nil, err
	}

	if oid != oidSignedData {
		return nil, errors.New("token is not CMS SignedData")
	}

	signedData, err := Read(children[1].Content, 0)
	if err != nil {
		return nil, err
	}

	fields, err := Children(signedData.Content)
	if err != nil {
		return nil, err
	}

	if len(fields) < 4 {
		return nil, errors.New("SignedData is malformed")
	}

	encap, err := Children(fields[2].Content)
	if err != nil {
		return nil, err
	}

	if len(encap) == 0 {
		return nil, errors.New("eContentType is not id-ct-TSTInfo")
	}

	oid, err = DecodeOID(encap[0].Content)
	if err != nil {
		return nil, err
	}

	if oid != oidTSTInfo {
		return nil, errors.New("eContentType is not id-ct-TSTInfo")
	}

	if len(encap) < 2 || encap[1].Class != 2 {
		return nil, errors.New("SignedData carries no eContent")
	}

	tstInfoOctets, err := Read(encap[1].Content, 0)
	if err != nil {
		return nil, err
	}

	tstInfoDER := tstInfoOctets.Content

	var certs [][]byte
	index := 3

	for index < len(fields) && fields[index].Class == 2 {
		if fields[index].Number == 0 {
			certificates, err := Children(fields[index].Content)
			if err != nil {
				return nil, err
			}

			for _, certificate := range certificates {
				certs = append(certs, Reencode(certificate))
			}
		}

		index++
	}

	if index >= len(fields) || fields[index].Number != 0x11 {
		return nil, errors.New("SignedData has no signerInfos")
	}

	signerInfos, err := Children(fields[index].Content)
	if err != nil {
		return nil, err
	}

	if len(signerInfos) == 0 {
		return nil, errors.New("signerInfos is empty")
	}

	signer, err := Children(signerInfos[0].Content)
	if err != nil {
		return nil, err
	}

	if len(signer) < 5 || signer[1].Number != 0x10 || signer[1].Class != 0 {
		return nil, errors.New("SignerInfo sid is not issuerAndSerialNumber")
	}

	sid, err := Children(signer[1].Content)
	if err != nil {
		return nil, err
	}

	digestAlg, err := Children(signer[2].Content)
	if err != nil {
		return nil, err
	}

	if len(sid) < 2 || len(digestAlg) == 0 {
		return nil, errors.New("SignerInfo is malformed")
	}

	if signer[3].Class != 2 || signer[3].Number != 0 {
		return nil, errors.New("SignerInfo has no signed attributes")
	}

	signedAttrsContent := signer[3].Content
	contentTypeAttr := ""
	var messageDigestAttr []byte

	attributes, err := Children(signedAttrsContent)
	if err != nil {
		return nil, err
	}

	for _, attribute := range attributes {
		parts, err := Children(attribute.Content)
		if err != nil {
			return nil, err
		}

		if len(parts) < 2 {
			continue
		}

		attrOID, err := DecodeOID(parts[0].Content)
		if err != nil {
			return nil, err
		}

		values, err := Children(parts[1].Content)
		if err != nil {
			return nil, err
		}

		if len(values) == 0 {
			continue
		}

		if attrOID == oidContentType {
			contentTypeAttr, err = DecodeOID(values[0].Content)
			if err != nil {
				return nil, err
			}
		}

		if attrOID == oidMessageDigest {
			messageDigestAttr = values[0].Content
		}
	}

	if contentTypeAttr == "" || len(messageDigestAttr) == 0 {
		return nil, errors.New("signed attributes lack contentType or messageDigest")
	}

	sigAlg, err := Children(signer[4].Content)
	if err != nil {
		return nil, err
	}

	if len(sigAlg) == 0 || len(signer) < 6 || signer[5].Number != 0x04 {
		return nil, errors.New("SignerInfo signature is malformed")
	}

	// TSTInfo: version, policy, messageImprint{alg, digest}, serial, genTime.
	tstInfoSequence, err := Read(tstInfoDER, 0)
	if err != nil {
		return nil, err
	}

	tstInfo, err := Children(tstInfoSequence.Content)
	if err != nil {
		return nil, err
	}

	if len(tstInfo) < 5 {
		return nil, errors.New("TSTInfo is malformed")
	}

	imprint, err := Children(tstInfo[2].Content)
	if err != nil {
		return nil, err
	}

	var imprintAlg []Element
	if len(imprint) > 0 {
		imprintAlg, err = Children(imprint[0].Content)
		if err != nil {
			return nil, err
		}
	}

	if len(imprint) < 2 || len(imprintAlg) == 0 {
		return nil, errors.New("TSTInfo messageImprint is malformed")
	}

	// Signature input: the signed attributes re-tagged as SET OF (RFC 5652
	// section 5.4). verify.php writes the short form by hand and the long
	// form through der_reencode; both are the minimal encoding.
	signedAttrsSet := Reencode(Element{Class: 0, Constructed: true, Number: 0x11, Content: signedAttrsContent})

	imprintAlgOID, err := DecodeOID(imprintAlg[0].Content)
	if err != nil {
		return nil, err
	}

	genTime, err := generalizedTime(tstInfo[4].Content)
	if err != nil {
		return nil, err
	}

	digestAlgOID, err := DecodeOID(digestAlg[0].Content)
	if err != nil {
		return nil, err
	}

	sigAlgOID, err := DecodeOID(sigAlg[0].Content)
	if err != nil {
		return nil, err
	}

	return &Token{
		ImprintAlg:        imprintAlgOID,
		Imprint:           imprint[1].Content,
		GenTime:           genTime,
		Certs:             certs,
		SignerIssuer:      Reencode(sid[0]),
		SignerSerial:      bytes.TrimLeft(sid[1].Content, "\x00"),
		SignedAttrsSet:    signedAttrsSet,
		ContentTypeAttr:   contentTypeAttr,
		MessageDigestAttr: messageDigestAttr,
		DigestAlg:         digestAlgOID,
		SigAlg:            sigAlgOID,
		Signature:         signer[5].Content,
		TSTInfo:           tstInfoDER,
	}, nil
}
