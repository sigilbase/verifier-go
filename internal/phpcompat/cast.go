package phpcompat

import (
	"math"
	"strconv"
)

// StringToInt reproduces PHP's (int) cast of a string: leading whitespace
// is skipped, the longest numeric prefix is read (an integer, or a float
// with a fraction or exponent that is then truncated), anything else yields
// 0, and a value beyond the int64 range saturates. verify.php applies this
// cast to the --size argument.
func StringToInt(s string) int64 {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\v' || s[i] == '\f') {
		i++
	}
	start := i
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	digitsStart := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	intEnd := i
	if intEnd == digitsStart {
		return 0
	}
	// A fraction or exponent makes the prefix a float, which PHP then
	// truncates toward zero, saturating at the int64 bounds.
	floatEnd := intEnd
	if i < len(s) && s[i] == '.' {
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		floatEnd = j
		i = j
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		j := i + 1
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		k := j
		for k < len(s) && s[k] >= '0' && s[k] <= '9' {
			k++
		}
		if k > j {
			floatEnd = k
		}
	}
	if floatEnd > intEnd {
		f, err := strconv.ParseFloat(s[start:floatEnd], 64)
		if err != nil && !isRangeError(err) {
			return 0
		}
		return saturatingFloatToInt(f)
	}
	v, err := strconv.ParseInt(s[start:intEnd], 10, 64)
	if err != nil {
		// Out of range: PHP saturates a numeric string.
		if s[start] == '-' {
			return math.MinInt64
		}
		return math.MaxInt64
	}
	return v
}

func isRangeError(err error) bool {
	if ne, ok := err.(*strconv.NumError); ok {
		return ne.Err == strconv.ErrRange
	}
	return false
}

// saturatingFloatToInt is the string path of PHP's cast: a float read from
// a numeric string saturates rather than wrapping.
func saturatingFloatToInt(f float64) int64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	if f >= 9223372036854775807.0 {
		return math.MaxInt64
	}
	if f <= -9223372036854775808.0 {
		return math.MinInt64
	}
	return int64(f)
}

// FloatToInt reproduces PHP's (int) cast of a float: NaN and infinities
// become 0, values inside the int64 range truncate toward zero, and values
// outside it wrap modulo 2^64 (zend_dval_to_lval on 64-bit builds).
// verify.php applies this cast to consistency proof tree sizes.
func FloatToInt(f float64) int64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	if f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
		return int64(f)
	}
	// Modular reduction of the truncated value into [0, 2^64), then
	// reinterpretation as a signed 64-bit integer.
	two64 := math.Ldexp(1, 64)
	m := math.Mod(math.Trunc(f), two64)
	if m < 0 {
		m += two64
	}
	// m is an integer-valued float in [0, 2^64); every such value that a
	// float64 can hold converts exactly through uint64.
	return int64(uint64(m))
}
