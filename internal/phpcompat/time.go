package phpcompat

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// pcreDollar reproduces the one way PCRE's "$" differs from Go's: without
// the D modifier it also matches before a single newline that ends the
// subject, so verify.php's anchored date patterns accept a value with one
// trailing LF (and only one). PHP's date parser then reads the value with
// the newline still attached and accepts it.
func pcreDollar(s string) string {
	if strings.HasSuffix(s, "\n") && !strings.HasSuffix(s, "\n\n") {
		return s[:len(s)-1]
	}
	return s
}

var rfc3339Shape = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$`)

// ParseRFC3339 reads a bundle timestamp the way verify.php's parse_rfc3339
// does: the shape is fixed by the regular expression above, and the value is
// then handed to PHP's date parser, which accepts and normalises out-of-range
// components inside these bounds (month 0..12, day 0..31, hour 0..24, minute
// 0..59, second 0..60, offset hour 0..24, offset minute 0..59) and refuses
// anything beyond them. Normalisation rolls over exactly as time.Date does:
// month 0 is December of the previous year, day 0 the last day of the
// previous month, hour 24 the next day, second 60 the next minute.
//
// The second result is false where PHP would either return null from the
// shape check or throw from the parser; both leave the verifier unable to
// trust the value, and verify.php treats them alike from 1.6.0.
func ParseRFC3339(s string) (time.Time, bool) {
	m := rfc3339Shape.FindStringSubmatch(pcreDollar(s))
	if m == nil {
		return time.Time{}, false
	}
	year, _ := strconv.Atoi(m[1])
	month, _ := strconv.Atoi(m[2])
	day, _ := strconv.Atoi(m[3])
	hour, _ := strconv.Atoi(m[4])
	minute, _ := strconv.Atoi(m[5])
	second, _ := strconv.Atoi(m[6])
	if month > 12 || day > 31 || hour > 24 || minute > 59 || second > 60 {
		return time.Time{}, false
	}
	nanos := 0
	if m[7] != "" {
		frac := m[7][1:]
		for len(frac) < 9 {
			frac += "0"
		}
		nanos, _ = strconv.Atoi(frac)
	}
	loc := time.UTC
	if m[8] != "Z" {
		sign := 1
		if m[8][0] == '-' {
			sign = -1
		}
		offHour, _ := strconv.Atoi(m[8][1:3])
		offMin, _ := strconv.Atoi(m[8][4:6])
		if offHour > 24 || offMin > 59 {
			return time.Time{}, false
		}
		loc = time.FixedZone("", sign*(offHour*3600+offMin*60))
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, nanos, loc), true
}

var generalizedTimeShape = regexp.MustCompile(`^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d{1,6})?Z$`)

// GeneralizedTime reads an ASN.1 GeneralizedTime the way verify.php's
// der_decode_generalized_time does: the shape is fixed, fractional seconds
// are ignored, and the components go through gmmktime, which normalises any
// value (month 13 is January of the next year) rather than rejecting it.
func GeneralizedTime(s string) (int64, bool) {
	m := generalizedTimeShape.FindStringSubmatch(pcreDollar(s))
	if m == nil {
		return 0, false
	}
	year, _ := strconv.Atoi(m[1])
	month, _ := strconv.Atoi(m[2])
	day, _ := strconv.Atoi(m[3])
	hour, _ := strconv.Atoi(m[4])
	minute, _ := strconv.Atoi(m[5])
	second, _ := strconv.Atoi(m[6])
	// gmmktime reads a two-digit-looking year the way mktime does: 0..69
	// mean 2000..2069 and 70..100 mean 1970..2000. A GeneralizedTime in
	// that range is not a date anyone will anchor against, but the two
	// verifiers have to read it alike.
	switch {
	case year >= 0 && year <= 69:
		year += 2000
	case year >= 70 && year <= 100:
		year += 1900
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC).Unix(), true
}

var utcTimeShape = regexp.MustCompile(`^(\d{2})(\d{10})Z$`)

// UTCTime reads an ASN.1 UTCTime as verify.php's der_decode_time does:
// two-digit years 50..99 mean 1950..1999 and 00..49 mean 2000..2049 (RFC
// 5280 section 4.1.2.5), after which the value is read as a GeneralizedTime.
func UTCTime(s string) (int64, bool) {
	m := utcTimeShape.FindStringSubmatch(pcreDollar(s))
	if m == nil {
		return 0, false
	}
	century := "20"
	if yy, _ := strconv.Atoi(m[1]); yy >= 50 {
		century = "19"
	}
	return GeneralizedTime(century + m[1] + m[2] + "Z")
}
