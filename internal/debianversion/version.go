// Package debianversion compares Debian package versions using the ordering
// defined by Debian Policy. It intentionally does not implement dpkg's
// dependency language; it only evaluates bounded version requirements.
package debianversion

import "strings"

// Compare returns -1, 0, or 1 according to Debian version ordering.
func Compare(left, right string) int {
	le, lu, lr := split(left)
	re, ru, rr := split(right)
	if le != re {
		if le < re {
			return -1
		}
		return 1
	}
	if value := comparePart(lu, ru); value != 0 {
		return value
	}
	return comparePart(lr, rr)
}

// Satisfies evaluates an inclusive minimum and exclusive maximum. Empty
// bounds are unbounded.
func Satisfies(version, minimum, maximum string) bool {
	return (minimum == "" || Compare(version, minimum) >= 0) && (maximum == "" || Compare(version, maximum) < 0)
}

func split(value string) (int, string, string) {
	epoch, rest := 0, value
	if index := strings.IndexByte(rest, ':'); index >= 0 {
		for _, digit := range rest[:index] {
			epoch = epoch*10 + int(digit-'0')
		}
		rest = rest[index+1:]
	}
	revision := ""
	if index := strings.LastIndexByte(rest, '-'); index >= 0 {
		revision, rest = rest[index+1:], rest[:index]
	}
	return epoch, rest, revision
}

func comparePart(left, right string) int {
	for len(left) > 0 || len(right) > 0 {
		// Debian compares non-digit runs using a special ordering: tilde,
		// end-of-string, letters, then all other characters.
		for {
			var leftChar, rightChar byte
			if len(left) > 0 && !isDigit(left[0]) {
				leftChar = left[0]
				left = left[1:]
			}
			if len(right) > 0 && !isDigit(right[0]) {
				rightChar = right[0]
				right = right[1:]
			}
			if value := strings.Compare(stringOrder(leftChar), stringOrder(rightChar)); value != 0 {
				return value
			}
			if (len(left) == 0 || isDigit(left[0])) && (len(right) == 0 || isDigit(right[0])) {
				break
			}
		}
		if len(left) == 0 || len(right) == 0 {
			if len(left) == 0 && len(right) == 0 {
				return 0
			}
			if len(left) == 0 {
				return -1
			}
			return 1
		}
		if !isDigit(left[0]) || !isDigit(right[0]) {
			continue
		}
		leftEnd, rightEnd := 0, 0
		for leftEnd < len(left) && isDigit(left[leftEnd]) {
			leftEnd++
		}
		for rightEnd < len(right) && isDigit(right[rightEnd]) {
			rightEnd++
		}
		leftDigits := strings.TrimLeft(left[:leftEnd], "0")
		rightDigits := strings.TrimLeft(right[:rightEnd], "0")
		if len(leftDigits) != len(rightDigits) {
			if len(leftDigits) < len(rightDigits) {
				return -1
			}
			return 1
		}
		if value := strings.Compare(leftDigits, rightDigits); value != 0 {
			return value
		}
		left, right = left[leftEnd:], right[rightEnd:]
	}
	return 0
}

func isDigit(value byte) bool { return value >= '0' && value <= '9' }

func stringOrder(value byte) string {
	switch {
	case value == '~':
		return "\x00"
	case value == 0:
		return "\x01"
	case value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z':
		return string([]byte{value + 2})
	default:
		// Keep punctuation after letters while retaining its byte ordering.
		return string([]byte{value + 0x82})
	}
}
