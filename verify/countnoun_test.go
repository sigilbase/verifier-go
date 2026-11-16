package verify

import "testing"

func TestCountNounAgreesInNumber(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{CountNoun(1, "problem"), "1 problem"},
		{CountNoun(0, "problem"), "0 problems"},
		{CountNoun(int64(2), "checkpoint"), "2 checkpoints"},
		{CountNoun(1, "Certificate of Evidence", "Certificates of Evidence"), "1 Certificate of Evidence"},
		{CountNoun(3, "Certificate of Evidence", "Certificates of Evidence"), "3 Certificates of Evidence"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}
