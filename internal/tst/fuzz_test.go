package tst

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func fuzzSeeds(f *testing.F) [][]byte {
	f.Helper()

	var seeds [][]byte

	for _, name := range []string{"freetsa-token.der", "dfn-token.der"} {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}

		seeds = append(seeds, data)
	}

	archive, err := zip.OpenReader(filepath.Join("..", "..", "corpus", "anchored.zip"))
	if err != nil {
		f.Fatal(err)
	}
	defer archive.Close()

	for _, file := range archive.File {
		if file.Name != "anchors.json" {
			continue
		}

		reader, err := file.Open()
		if err != nil {
			f.Fatal(err)
		}

		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			f.Fatal(err)
		}

		var document struct {
			Anchors []struct {
				Token string `json:"token"`
			} `json:"anchors"`
		}

		if err := json.Unmarshal(data, &document); err != nil {
			f.Fatal(err)
		}

		for _, anchor := range document.Anchors {
			der, err := base64.StdEncoding.DecodeString(anchor.Token)
			if err != nil {
				f.Fatal(err)
			}

			seeds = append(seeds, der)
		}
	}

	return seeds
}

// FuzzParseToken: no input may make the parser or the validator panic, and
// nothing about a hostile token may be trusted beyond what Validate
// reports. A CA is supplied so the chain walk runs on any token that
// parses.
func FuzzParseToken(f *testing.F) {
	for _, seed := range fuzzSeeds(f) {
		f.Add(seed)
	}

	ca, err := os.ReadFile(filepath.Join("..", "..", "corpus", "anchor-ca.pem"))
	if err != nil {
		f.Fatal(err)
	}

	caPEM := string(ca)
	message := make([]byte, 32)

	f.Fuzz(func(t *testing.T, data []byte) {
		token, err := ParseToken(data)
		if err != nil {
			return
		}

		Validate(token, message, nil)
		Validate(token, message, &caPEM)

		for _, certificate := range token.Certs {
			IssuerProblems(certificate, token.GenTime, 0)
		}
	})
}

// FuzzRead: the DER reader and the deep re-encoder must never panic, and
// re-encoding what was read must itself read back.
func FuzzRead(f *testing.F) {
	for _, seed := range fuzzSeeds(f) {
		f.Add(seed)
	}

	f.Add([]byte{0x30, 0x82, 0x00, 0x03, 0x02, 0x01, 0x05})
	f.Add([]byte{0x1f, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		element, err := Read(data, 0)
		if err != nil {
			return
		}

		again, err := Read(Reencode(element), 0)
		if err != nil || again.Number != element.Number || len(again.Content) != len(element.Content) {
			t.Fatalf("re-encoded element does not read back: %v", err)
		}

		if _, err := Read(ReencodeDeep(element), 0); err != nil {
			t.Fatalf("deep re-encoding does not read back: %v", err)
		}

		Children(element.Content)
		DecodeOID(element.Content)
		ParseCertParts(data)
		PEMCertificates(string(data))
	})
}
