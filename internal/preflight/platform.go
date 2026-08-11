package preflight

import (
	"bufio"
	"strings"
)

// PlatformInfo is a read-only parse result. S7 owns exact profile
// qualification and must not infer support from ID_LIKE.
type PlatformInfo struct {
	ID         string `json:"id,omitempty"`
	IDLike     string `json:"id_like,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`
}

func ParseOSRelease(content string) PlatformInfo {
	info := PlatformInfo{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = parseOSReleaseValue(value)
		switch strings.TrimSpace(key) {
		case "ID":
			info.ID = value
		case "ID_LIKE":
			info.IDLike = value
		case "VERSION_ID":
			info.VersionID = value
		case "PRETTY_NAME":
			info.PrettyName = value
		}
	}
	return info
}

func parseOSReleaseValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if quote := value[0]; quote == '"' || quote == '\'' {
		return parseQuotedOSReleaseValue(value[1:], quote)
	}
	return unescapeOSReleaseValue(value)
}

func parseQuotedOSReleaseValue(value string, quote byte) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == quote {
			return builder.String()
		}
		if quote == '"' && character == '\\' && index+1 < len(value) {
			index++
			builder.WriteByte(value[index])
			continue
		}
		builder.WriteByte(character)
	}
	return builder.String()
}

func unescapeOSReleaseValue(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+1 < len(value) {
			index++
		}
		builder.WriteByte(value[index])
	}
	return builder.String()
}
