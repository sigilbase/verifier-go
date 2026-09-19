package tst

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// corpusAnchor is one entry of the conformance corpus's anchors.json.
type corpusAnchor struct {
	CheckpointHash string `json:"checkpoint_hash"`
	Token          string `json:"token"`
	TokenHash      string `json:"token_hash"`
	CAPEM          string `json:"ca_pem"`
}

func loadCorpusAnchors(t *testing.T) []corpusAnchor {
	t.Helper()

	archive, err := zip.OpenReader(filepath.Join("..", "..", "corpus", "anchored.zip"))
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer archive.Close()

	for _, file := range archive.File {
		if file.Name != "anchors.json" {
			continue
		}

		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}

		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}

		var document struct {
			Anchors []corpusAnchor `json:"anchors"`
		}

		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}

		return document.Anchors
	}

	t.Fatal("anchored.zip has no anchors.json")

	return nil
}

func corpusCA(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "corpus", "anchor-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func corpusToken(t *testing.T) (*Token, []byte, string) {
	t.Helper()

	anchor := loadCorpusAnchors(t)[0]

	der, err := base64.StdEncoding.DecodeString(anchor.Token)
	if err != nil {
		t.Fatal(err)
	}

	token, err := ParseToken(der)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}

	return token, mustHex(t, anchor.CheckpointHash), anchor.CAPEM
}

func realToken(t *testing.T, name string) (*Token, []byte) {
	t.Helper()

	der, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}

	token, err := ParseToken(der)
	if err != nil {
		t.Fatalf("ParseToken(%s): %v", name, err)
	}

	return token, der
}

func selfSignedRootPEM(t *testing.T, token *Token) string {
	t.Helper()

	for _, certificate := range token.Certs {
		parts, err := ParseCertParts(certificate)
		if err != nil {
			continue
		}

		if bytes.Equal(parts.Issuer, parts.Subject) {
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
		}
	}

	t.Fatal("token carries no self-signed root")

	return ""
}

const realMessageHex = "b4f5900d7e2d8ee629476a0d2183fd8b8140a81d92635a08524cda35735c802a"

func expectFailures(t *testing.T, got []string, want ...string) {
	t.Helper()

	if len(want) == 0 {
		want = nil
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("failures = %q; want %q", got, want)
	}
}

func TestCorpusTokenParses(t *testing.T) {
	token, message, _ := corpusToken(t)

	if token.ImprintAlg != "2.16.840.1.101.3.4.2.1" || token.DigestAlg != "2.16.840.1.101.3.4.2.1" || token.SigAlg != "1.2.840.113549.1.1.11" {
		t.Errorf("algorithms = %s %s %s", token.ImprintAlg, token.DigestAlg, token.SigAlg)
	}

	if token.ContentTypeAttr != oidTSTInfo || len(token.MessageDigestAttr) != 32 || len(token.Certs) != 2 {
		t.Errorf("token = %+v", token)
	}

	if !bytes.Equal(token.SignerSerial, []byte{0x02}) {
		t.Errorf("signer serial = %x", token.SignerSerial)
	}

	// 2026-09-11T19:31:34Z, the moment the corpus was generated.
	if token.GenTime != 1789155094 {
		t.Errorf("genTime = %d", token.GenTime)
	}

	if len(message) != 32 {
		t.Errorf("message length %d", len(message))
	}
}

func TestCorpusTokenValidates(t *testing.T) {
	token, message, bundleCA := corpusToken(t)
	ca := corpusCA(t)

	expectFailures(t, Validate(token, message, &ca))
	expectFailures(t, Validate(token, message, &bundleCA))
	expectFailures(t, Validate(token, message, nil))

	second := loadCorpusAnchors(t)[1]
	der, _ := base64.StdEncoding.DecodeString(second.Token)
	other, err := ParseToken(der)
	if err != nil {
		t.Fatal(err)
	}
	expectFailures(t, Validate(other, mustHex(t, second.CheckpointHash), &ca))

	// The first anchor's token does not attest to the second checkpoint.
	expectFailures(t, Validate(token, mustHex(t, second.CheckpointHash), &ca), "the token message imprint does not match the checkpoint hash")
}

func TestCorpusTokenAgainstADifferentRoot(t *testing.T) {
	token, message, _ := corpusToken(t)
	freetsa, _ := realToken(t, "freetsa-token.der")
	other := selfSignedRootPEM(t, freetsa)

	expectFailures(t, Validate(token, message, &other), "the chain terminates at a root that is not in the provided CA")
}

func TestCorpusTokenTamperedSignature(t *testing.T) {
	token, message, _ := corpusToken(t)
	ca := corpusCA(t)

	tampered := *token
	tampered.Signature = append([]byte{}, token.Signature...)
	tampered.Signature[0] ^= 0x01

	expectFailures(t, Validate(&tampered, message, &ca), "the CMS signature over the signed attributes does not verify")
}

func TestCorpusTokenOtherFailures(t *testing.T) {
	token, message, _ := corpusToken(t)
	ca := corpusCA(t)

	empty := "no certificates here"
	expectFailures(t, Validate(token, message, &empty), "the provided CA chain contains no certificates")

	wrongContentType := *token
	wrongContentType.ContentTypeAttr = "1.2.840.113549.1.7.1"
	expectFailures(t, Validate(&wrongContentType, message, &ca), "the signed contentType attribute is not id-ct-TSTInfo")

	wrongImprintAlg := *token
	wrongImprintAlg.ImprintAlg = "1.3.14.3.2.26"
	expectFailures(t, Validate(&wrongImprintAlg, message, &ca), "unsupported imprint algorithm [1.3.14.3.2.26]")

	wrongDigestAlg := *token
	wrongDigestAlg.DigestAlg = "1.3.14.3.2.26"
	expectFailures(t, Validate(&wrongDigestAlg, message, &ca), "unsupported digest algorithm [1.3.14.3.2.26]")

	wrongSigAlg := *token
	wrongSigAlg.SigAlg = "1.2.840.113549.1.1.5"
	expectFailures(t, Validate(&wrongSigAlg, message, &ca), "unsupported signature algorithm [1.2.840.113549.1.1.5]")

	wrongDigest := *token
	wrongDigest.MessageDigestAttr = make([]byte, 32)
	expectFailures(t, Validate(&wrongDigest, message, &ca), "the messageDigest attribute does not match the TSTInfo content")

	noCerts := *token
	noCerts.Certs = nil
	expectFailures(t, Validate(&noCerts, message, &ca), "the signer certificate is not embedded in the token")

	// Only the root embedded: the signer is missing, and the chain cannot
	// even start.
	rootOnly := *token
	rootOnly.Certs = token.Certs[1:]
	expectFailures(t, Validate(&rootOnly, message, &ca), "the signer certificate is not embedded in the token")

	// Signer only, no CA: nothing to chain to, and no chain is asked for.
	signerOnly := *token
	signerOnly.Certs = token.Certs[:1]
	expectFailures(t, Validate(&signerOnly, message, nil))

	// Signer only, with a CA that does not hold its issuer.
	freetsa, _ := realToken(t, "freetsa-token.der")
	other := selfSignedRootPEM(t, freetsa)
	expectFailures(t, Validate(&signerOnly, message, &other), "the certificate chain is incomplete: an issuer certificate is missing")

	// genTime outside the signer's validity: 2020.
	early := *token
	early.GenTime = 1577836800
	expectFailures(t, Validate(&early, message, &ca),
		"the signer certificate was not valid at genTime",
		"an issuer certificate in the chain was not valid at genTime",
	)
}

func TestRealTokensValidate(t *testing.T) {
	message := mustHex(t, realMessageHex)
	fakeCA := corpusCA(t)

	for _, name := range []string{"freetsa-token.der", "dfn-token.der"} {
		token, _ := realToken(t, name)

		expectFailures(t, Validate(token, message, nil))

		own := selfSignedRootPEM(t, token)
		expectFailures(t, Validate(token, message, &own))

		expectFailures(t, Validate(token, message, &fakeCA), "the chain terminates at a root that is not in the provided CA")

		wrong := make([]byte, 32)
		expectFailures(t, Validate(token, wrong, &own), "the token message imprint does not match the checkpoint hash")

		tampered := *token
		tampered.Signature = append([]byte{}, token.Signature...)
		tampered.Signature[len(tampered.Signature)/2] ^= 0x40
		expectFailures(t, Validate(&tampered, message, &own), "the CMS signature over the signed attributes does not verify")
	}

	freetsa, _ := realToken(t, "freetsa-token.der")
	if freetsa.SigAlg != "1.2.840.10045.4.3.4" || freetsa.GenTime != 1784427005 {
		t.Errorf("FreeTSA token: sigalg %s genTime %d", freetsa.SigAlg, freetsa.GenTime)
	}

	dfn, _ := realToken(t, "dfn-token.der")
	if dfn.SigAlg != "1.2.840.113549.1.1.11" || len(dfn.Certs) != 3 {
		t.Errorf("DFN token: sigalg %s certs %d", dfn.SigAlg, len(dfn.Certs))
	}
}

func TestRealTokenChainWithSignerOnly(t *testing.T) {
	// The DFN chain needs its intermediate: without it, and with only the
	// root as CA, the walk stops at the missing issuer.
	dfn, _ := realToken(t, "dfn-token.der")
	own := selfSignedRootPEM(t, dfn)
	message := mustHex(t, realMessageHex)

	var signerOnly [][]byte
	for _, certificate := range dfn.Certs {
		parts, err := ParseCertParts(certificate)
		if err != nil {
			t.Fatal(err)
		}

		if bytes.Equal(parts.Serial, dfn.SignerSerial) && bytes.Equal(parts.Issuer, dfn.SignerIssuer) {
			signerOnly = append(signerOnly, certificate)
		}
	}

	if len(signerOnly) != 1 {
		t.Fatalf("found %d signer certificates", len(signerOnly))
	}

	stripped := *dfn
	stripped.Certs = signerOnly
	expectFailures(t, Validate(&stripped, message, &own), "the certificate chain is incomplete: an issuer certificate is missing")
}

func TestParseTokenErrors(t *testing.T) {
	_, corpusDER := realToken(t, "freetsa-token.der")

	if _, err := ParseToken(nil); err == nil || err.Error() != "truncated DER element" {
		t.Errorf("empty token: %v", err)
	}

	// An OCTET STRING at the top: not CMS at all.
	if _, err := ParseToken([]byte{0x04, 0x02, 0x01, 0x02}); err == nil {
		t.Errorf("non-CMS token accepted")
	}

	// A ContentInfo whose contentType is id-data rather than SignedData.
	notSigned := []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x00}
	if _, err := ParseToken(notSigned); err == nil || err.Error() != "token is not CMS SignedData" {
		t.Errorf("id-data token: %v", err)
	}

	// The real token with its last byte cut off: the outer length no
	// longer fits.
	if _, err := ParseToken(corpusDER[:len(corpusDER)-1]); err == nil || err.Error() != "truncated DER content" {
		t.Errorf("truncated token: %v", err)
	}
}

func TestPEMCertificates(t *testing.T) {
	ca := corpusCA(t)

	certificates := PEMCertificates(ca)
	if len(certificates) != 1 {
		t.Fatalf("got %d certificates from anchor-ca.pem", len(certificates))
	}

	parts, err := ParseCertParts(certificates[0])
	if err != nil || !bytes.Equal(parts.Issuer, parts.Subject) {
		t.Errorf("anchor-ca.pem is not a self-signed certificate: %v", err)
	}

	// Two blocks, CRLF line endings, text around them, vertical tabs and
	// form feeds inside the body: PHP's \s strips them all.
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(ca), "-----BEGIN CERTIFICATE-----"), "-----END CERTIFICATE-----"))
	twice := "prefix text\r\n-----BEGIN CERTIFICATE-----\r\n" + strings.ReplaceAll(body, "\n", "\r\n") +
		"\r\n-----END CERTIFICATE-----\r\nmiddle\n-----BEGIN CERTIFICATE-----\v" + strings.ReplaceAll(body, "\n", "\f") +
		"-----END CERTIFICATE-----trailing"

	if got := PEMCertificates(twice); len(got) != 2 || !bytes.Equal(got[0], certificates[0]) || !bytes.Equal(got[1], certificates[0]) {
		t.Errorf("two blocks: got %d certificates", len(got))
	}

	if got := PEMCertificates("nothing here"); len(got) != 0 {
		t.Errorf("no blocks: got %d", len(got))
	}

	if got := PEMCertificates("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"); len(got) != 0 {
		t.Errorf("invalid base64: got %d", len(got))
	}

	// An empty body cannot match the lazy .+? and a body of only padding
	// decodes to nothing, so neither yields a certificate.
	if got := PEMCertificates("-----BEGIN CERTIFICATE----------END CERTIFICATE----------BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----"); len(got) != 0 {
		t.Errorf("empty bodies: got %d", len(got))
	}
}

// rebuildCertificate re-encodes a certificate with its extension list
// replaced, leaving the signature stale. IssuerProblems never checks the
// signature, so that is enough to exercise its rules.
func rebuildCertificate(t *testing.T, der []byte, edit func(extensions []Element) []Element) []byte {
	t.Helper()

	certificate, err := Read(der, 0)
	if err != nil {
		t.Fatal(err)
	}

	children, err := Children(certificate.Content)
	if err != nil {
		t.Fatal(err)
	}

	fields, err := Children(children[0].Content)
	if err != nil {
		t.Fatal(err)
	}

	var tbsContent []byte

	for _, field := range fields {
		if field.Class == 2 && field.Number == 3 {
			sequence, err := Read(field.Content, 0)
			if err != nil {
				t.Fatal(err)
			}

			list, err := Children(sequence.Content)
			if err != nil {
				t.Fatal(err)
			}

			list = edit(list)
			if list == nil {
				continue
			}

			var inner []byte
			for _, extension := range list {
				inner = append(inner, Reencode(extension)...)
			}

			wrapped := Reencode(Element{Class: 0, Constructed: true, Number: 0x10, Content: inner})
			tbsContent = append(tbsContent, Reencode(Element{Class: 2, Constructed: true, Number: 3, Content: wrapped})...)

			continue
		}

		tbsContent = append(tbsContent, Reencode(field)...)
	}

	var content []byte
	content = append(content, Reencode(Element{Class: 0, Constructed: true, Number: 0x10, Content: tbsContent})...)
	content = append(content, Reencode(children[1])...)
	content = append(content, Reencode(children[2])...)

	return Reencode(Element{Class: 0, Constructed: true, Number: 0x10, Content: content})
}

func TestIssuerProblems(t *testing.T) {
	token, _, _ := corpusToken(t)
	signer, root := token.Certs[0], token.Certs[1]
	genTime := token.GenTime

	expectFailures(t, IssuerProblems(root, genTime, 0))
	expectFailures(t, IssuerProblems(root, genTime, 7))

	// 2020: before the root's notBefore.
	expectFailures(t, IssuerProblems(root, 1577836800, 0), "an issuer certificate in the chain was not valid at genTime")

	// The signer is an end-entity: cA FALSE and keyUsage digitalSignature only.
	expectFailures(t, IssuerProblems(signer, genTime, 0),
		"an issuer certificate in the chain is not a CA: basicConstraints cA is FALSE",
		"an issuer certificate in the chain is not permitted to sign certificates: keyUsage lacks keyCertSign",
	)

	// Both rules at once, with the validity problem first.
	expectFailures(t, IssuerProblems(signer, 1577836800, 0),
		"an issuer certificate in the chain was not valid at genTime",
		"an issuer certificate in the chain is not a CA: basicConstraints cA is FALSE",
		"an issuer certificate in the chain is not permitted to sign certificates: keyUsage lacks keyCertSign",
	)

	// No extensions at all: an absent basicConstraints counts as FALSE.
	bare := rebuildCertificate(t, signer, func([]Element) []Element { return nil })
	expectFailures(t, IssuerProblems(bare, genTime, 0), "an issuer certificate in the chain is not a CA: it carries no basicConstraints extension")

	// A CA whose keyUsage lacks keyCertSign: the root with its key usage
	// bits rewritten to digitalSignature only.
	noCertSign := rebuildCertificate(t, root, func(list []Element) []Element {
		out := make([]Element, 0, len(list))
		for _, extension := range list {
			fields, err := Children(extension.Content)
			if err != nil {
				t.Fatal(err)
			}

			oid, _ := DecodeOID(fields[0].Content)
			if oid == oidKeyUsage {
				var content []byte
				for i, field := range fields {
					if i == len(fields)-1 {
						field = Element{Class: 0, Number: 0x04, Content: []byte{0x03, 0x02, 0x07, 0x80}}
					}
					content = append(content, Reencode(field)...)
				}
				extension = Element{Class: 0, Constructed: true, Number: 0x10, Content: content}
			}

			out = append(out, extension)
		}

		return out
	})
	expectFailures(t, IssuerProblems(noCertSign, genTime, 0), "an issuer certificate in the chain is not permitted to sign certificates: keyUsage lacks keyCertSign")

	// A malformed basicConstraints value: not a SEQUENCE.
	malformed := rebuildCertificate(t, root, func(list []Element) []Element {
		out := make([]Element, 0, len(list))
		for _, extension := range list {
			fields, err := Children(extension.Content)
			if err != nil {
				t.Fatal(err)
			}

			oid, _ := DecodeOID(fields[0].Content)
			if oid == oidBasicConstraints {
				var content []byte
				for i, field := range fields {
					if i == len(fields)-1 {
						field = Element{Class: 0, Number: 0x04, Content: []byte{0x04, 0x01, 0xff}}
					}
					content = append(content, Reencode(field)...)
				}
				extension = Element{Class: 0, Constructed: true, Number: 0x10, Content: content}
			}

			out = append(out, extension)
		}

		return out
	})
	expectFailures(t, IssuerProblems(malformed, genTime, 0), "an issuer certificate in the chain has a malformed basicConstraints extension")

	expectFailures(t, IssuerProblems([]byte{0x30, 0x00}, genTime, 0), "an issuer certificate in the chain does not parse")
	expectFailures(t, IssuerProblems(nil, genTime, 0), "an issuer certificate in the chain does not parse")
}

func TestIssuerProblemsPathLength(t *testing.T) {
	dfn, _ := realToken(t, "dfn-token.der")

	// The DFN issuing CA is the certificate whose subject is the signer's
	// issuer; it carries pathLenConstraint 1.
	var issuing []byte
	for _, certificate := range dfn.Certs {
		parts, err := ParseCertParts(certificate)
		if err != nil {
			t.Fatal(err)
		}

		if bytes.Equal(parts.Subject, dfn.SignerIssuer) {
			issuing = certificate
		}
	}

	if issuing == nil {
		t.Fatal("issuing CA not found")
	}

	expectFailures(t, IssuerProblems(issuing, dfn.GenTime, 0))
	expectFailures(t, IssuerProblems(issuing, dfn.GenTime, 1))
	expectFailures(t, IssuerProblems(issuing, dfn.GenTime, 2), "an issuer certificate in the chain has more intermediates beneath it than its pathLenConstraint allows")
}

func TestValidateChainIsNotConfusedByAForeignTokenRoot(t *testing.T) {
	// A root inside the token is never an anchor by itself: the corpus
	// token carries its own root, yet only the CA argument decides.
	token, message, _ := corpusToken(t)
	dfn, _ := realToken(t, "dfn-token.der")
	dfnRoot := selfSignedRootPEM(t, dfn)

	expectFailures(t, Validate(token, message, &dfnRoot), "the chain terminates at a root that is not in the provided CA")
}
