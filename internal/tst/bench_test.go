package tst

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkParseAndValidate(b *testing.B) {
	der, err := os.ReadFile(filepath.Join("testdata", "dfn-token.der"))
	if err != nil {
		b.Fatal(err)
	}

	ca, err := os.ReadFile(filepath.Join("..", "..", "corpus", "anchor-ca.pem"))
	if err != nil {
		b.Fatal(err)
	}

	caPEM := string(ca)
	message := make([]byte, 32)

	for i := 0; i < b.N; i++ {
		token, err := ParseToken(der)
		if err != nil {
			b.Fatal(err)
		}

		Validate(token, message, &caPEM)
	}
}
