package phpcompat

import (
	"math"
	"testing"
)

// Every expectation below was observed by running the PHP construct it
// mirrors under PHP 8.4.25 (see vectors/vectors.json, "php_behaviour").

func TestBase64StrictMatchesPHP(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"YQ", "a", true},
		{"YQ=", "", false},
		{"YQ==", "a", true},
		{"YQ===", "", false},
		{"Y", "", false},
		{"YQ==YQ==", "", false},
		{"YW Jj", "abc", true},
		{"YWJj", "abc", true},
		{"YW\nJj", "abc", true}, // a real newline is whitespace and is skipped
		{"YW*Jj", "", false},
		{"", "", true},
		{"====", "", false},
		{"YQ==\n", "a", true},
		{"YQ==\\n", "", false}, // a backslash is outside the alphabet
		{"YWJjZA==", "abcd", true},
		{"YWJjZA", "abcd", true},
		{"YWJjZ", "", false},
		{"YWJjZQ", "abce", true},
		{"YWJj\r\n", "abc", true},
	}
	for _, c := range cases {
		got, ok := Base64Strict(c.in)
		if ok != c.ok || (ok && string(got) != c.want) {
			t.Errorf("Base64Strict(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestStringToIntMatchesPHP(t *testing.T) {
	cases := map[string]int64{
		"1e3": 1000, "1.9": 1, "-1.9": -1, " 12": 12, "12abc": 12, "abc": 0, "0x1A": 0,
		"-5": -5, "+5": 5, "1e400": 0, "9223372036854775808": math.MaxInt64,
		"9223372036854775807": math.MaxInt64, "  -0": 0, "": 0, "1e19": math.MaxInt64,
		"0b11": 0, "007": 7, "1_000": 1, "12\n": 12, "\n12": 12, " 1 2": 1,
		"-9223372036854775809": math.MinInt64,
	}
	for in, want := range cases {
		if got := StringToInt(in); got != want {
			t.Errorf("StringToInt(%q) = %d; want %d", in, got, want)
		}
	}
}

func TestFloatToIntMatchesPHP(t *testing.T) {
	cases := []struct {
		in   float64
		want int64
	}{
		{1e30, 5076964154930102272},
		{-1e30, -5076964154930102272},
		{math.NaN(), 0},
		{math.Inf(1), 0},
		{1.9, 1},
		{-1.9, -1},
		{9.3e18, -9146744073709551616},
		{1.8446744073709552e19, 0},
		{math.Ldexp(1, 63), math.MinInt64},
		{4294967296.5, 4294967296},
		{-0.5, 0},
	}
	for _, c := range cases {
		if got := FloatToInt(c.in); got != c.want {
			t.Errorf("FloatToInt(%v) = %d; want %d", c.in, got, c.want)
		}
	}
}

func TestParseRFC3339MatchesPHP(t *testing.T) {
	accept := map[string]int64{
		"2026-01-02T03:04:05Z":        1767323045,
		"2026-01-02T03:04:05.123456Z": 1767323045,
		"2026-00-01T00:00:00Z":        1764547200, // month 0 rolls to December 2025
		"2026-02-30T00:00:00Z":        1772409600, // rolls to 2 March
		"2026-02-29T00:00:00Z":        1772323200,
		"2026-01-00T00:00:00Z":        1767139200, // day 0 rolls to 31 December 2025
		"2026-01-01T24:00:00Z":        1767312000,
		"2026-01-01T23:59:60Z":        1767312000,
		"2026-01-01T00:00:00+01:00":   1767222000,
		"2026-01-01T00:00:00-00:00":   1767225600,
		"0000-01-01T00:00:00Z":        -62167219200,
		"9999-12-31T23:59:59Z":        253402300799,
		"2026-01-01T00:00:00+24:00":   1767139200,
		"2026-01-01T00:00:00+24:59":   1767135660,
		"2026-01-01T00:00:00-24:00":   1767312000,
		"2026-01-01T00:00:00+23:59":   1767139260,
		"2026-01-01T00:00:00.5Z":      1767225600,
		"2026-02-31T00:00:00Z":        1772496000,
		"2027-02-29T00:00:00Z":        1803859200,
		"2026-04-31T00:00:00Z":        1777593600,
		"2026-12-31T24:00:00Z":        1798761600,
		"2026-06-30T23:59:60Z":        1782864000,
		"2026-01-01T24:00:01Z":        1767312001,
		"2026-01-01T24:30:00Z":        1767313800,
		"2026-01-02T03:04:05Z\n":      1767323045, // PCRE's $ matches before one final newline
	}
	for in, want := range accept {
		got, ok := ParseRFC3339(in)
		if !ok || got.Unix() != want {
			t.Errorf("ParseRFC3339(%q) = %v, %v; want unix %d", in, got, ok, want)
		}
	}
	reject := []string{
		"2026-01-02T03:04:05.1234567Z", "2026-01-02T03:04:05.Z", "2026-13-01T00:00:00Z",
		"2026-01-32T00:00:00Z", "2026-01-01T25:00:00Z", "2026-01-01T23:60:00Z",
		"2026-01-01T23:59:61Z", "2026-01-01T00:00:00+25:00", "2026-01-01T00:00:00+01:60",
		"2026-01-01t00:00:00Z", "2026-01-01T00:00:00z", "2026-01-01T00:00:00+99:99",
		"2026-01-01T00:00:00+00:60", "2026-1-01T00:00:00Z", "2026-01-01T00:00:00,5Z",
		"2026-01-01T00:00:00 Z", "", "2026-01-01",
		"2026-01-02T03:04:05Z\n\n", "2026-01-02T03:04:05Z\r\n", "\n2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z ",
	}
	for _, in := range reject {
		if _, ok := ParseRFC3339(in); ok {
			t.Errorf("ParseRFC3339(%q) accepted; PHP rejects or throws", in)
		}
	}
	// Microseconds take part in comparisons, exactly as DateTimeImmutable's do.
	a, _ := ParseRFC3339("2026-01-01T00:00:00.000001Z")
	b, _ := ParseRFC3339("2026-01-01T00:00:00Z")
	if !a.After(b) {
		t.Errorf("microsecond precision lost")
	}
	c, _ := ParseRFC3339("2026-01-01T01:00:00+01:00")
	if !c.Equal(b) {
		t.Errorf("offset not applied: %v vs %v", c, b)
	}
}

func TestGeneralizedTimeMatchesPHP(t *testing.T) {
	accept := map[string]int64{
		"20260102030405Z":   1767323045,
		"20260102030405.5Z": 1767323045,
		"20261301000000Z":   1798761600,
		"20260230000000Z":   1772409600,
		"20260101235960Z":   1767312000,
		"20260101240000Z":   1767312000,
		"00000101000000Z":   946684800, // PHP's gmmktime reads year 0 as 2000
		"99991231235959Z":   253402300799,
		"20260000000000Z":   1764460800,
		"20260102030405Z\n": 1767323045,
	}
	for in, want := range accept {
		got, ok := GeneralizedTime(in)
		if !ok || got != want {
			t.Errorf("GeneralizedTime(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"20260102030405.1234567Z", "2026010203Z", "20260102030405+0100", "", "20260102030405Z\n\n"} {
		if _, ok := GeneralizedTime(in); ok {
			t.Errorf("GeneralizedTime(%q) accepted; PHP throws", in)
		}
	}
	utc := map[string]int64{"260102030405Z": 1767323045, "500102030405Z": -631054555, "490102030405Z": 2493169445, "260102030405Z\n": 1767323045}
	for in, want := range utc {
		got, ok := UTCTime(in)
		if !ok || got != want {
			t.Errorf("UTCTime(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"2601020304Z", "260102030405+0100"} {
		if _, ok := UTCTime(in); ok {
			t.Errorf("UTCTime(%q) accepted; PHP throws", in)
		}
	}
}
