package sensitive

import (
	"regexp"
	"strings"
)

var urlUserinfoPattern = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@]+@`)

func ContainsText(text string) bool {
	if ContainsURLUserinfo(text) {
		return true
	}
	words := strings.Fields(text)
	for i, word := range words {
		lower := strings.ToLower(word)
		next := ""
		if i+1 < len(words) {
			next = strings.ToLower(words[i+1])
		}
		if containsSensitiveWord(lower) || containsSensitivePhrase(lower, next) {
			return true
		}
	}
	return false
}

func ContainsURLUserinfo(text string) bool {
	return urlUserinfoPattern.MatchString(text)
}

func RedactText(text string) string {
	text = urlUserinfoPattern.ReplaceAllString(text, "${1}[redacted]@")
	words := strings.Fields(text)
	for i, word := range words {
		lower := strings.ToLower(word)
		next := ""
		if i+1 < len(words) {
			next = strings.ToLower(words[i+1])
		}
		if containsSensitiveWord(lower) || containsSensitivePhrase(lower, next) {
			for j := i; j < len(words); j++ {
				words[j] = "[redacted]"
			}
			break
		}
	}
	return strings.Join(words, " ")
}

func containsSensitiveWord(lower string) bool {
	label := sensitiveLabel(lower)
	if label == "stdout" || label == "stderr" {
		return true
	}
	return strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "preauth") ||
		strings.Contains(lower, "authkey") ||
		strings.Contains(lower, "cookie") ||
		lower == "bearer" ||
		lower == "basic" ||
		strings.HasPrefix(lower, "bearer=") ||
		strings.HasPrefix(lower, "basic=") ||
		strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "api-key") ||
		strings.Contains(lower, "apikey") ||
		strings.Contains(lower, "x-api-key") ||
		strings.Contains(lower, "access_key") ||
		strings.Contains(lower, "access-key") ||
		strings.Contains(lower, "accesskey") ||
		strings.Contains(lower, "client_secret") ||
		strings.Contains(lower, "client-secret") ||
		strings.Contains(lower, "clientsecret") ||
		strings.HasPrefix(lower, "mkey:") ||
		strings.Contains(lower, "tskey-auth") ||
		strings.Contains(lower, "hskey-auth") ||
		strings.Contains(lower, "authorization")
}

func containsSensitivePhrase(lower string, next string) bool {
	lower = sensitiveLabel(lower)
	next = sensitiveLabel(next)
	switch lower {
	case "api", "x-api", "access":
		return next == "key"
	case "client":
		return next == "secret"
	default:
		return false
	}
}

func sensitiveLabel(value string) string {
	value = strings.Trim(value, " \t\r\n\"'`")
	if label, _, ok := strings.Cut(value, "="); ok {
		value = label
	}
	if label, _, ok := strings.Cut(value, ":"); ok {
		value = label
	}
	return strings.Trim(value, " \t\r\n\"'`")
}
