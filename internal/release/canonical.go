// Package release defines checksum-only candidate and final release identity.
package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const MaximumCanonicalDocumentBytes = 8 << 20

// DecodeCanonical rejects unknown fields, duplicate names, trailing values,
// non-canonical encodings, and documents outside the fixed byte bound.
func DecodeCanonical(data []byte, destination any) error {
	if destination == nil || len(data) == 0 || len(data) > MaximumCanonicalDocumentBytes {
		return fmt.Errorf("canonical JSON destination or size is invalid")
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("canonical JSON is not valid UTF-8")
	}
	if err := rejectDuplicateNames(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode canonical JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("canonical JSON has trailing data")
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, data) {
		return fmt.Errorf("JSON bytes are not canonical")
	}
	return nil
}

func MarshalCanonical(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > MaximumCanonicalDocumentBytes {
		return nil, fmt.Errorf("canonical JSON exceeds its fixed byte bound")
	}
	return data, nil
}

func DigestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func ValidReference(value string) bool {
	return refPattern.MatchString(value)
}

func ValidDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func rejectDuplicateNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder, "$", 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("scan canonical JSON suffix: %w", err)
		}
		return fmt.Errorf("canonical JSON has another value beginning with %v", token)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, path string, depth int) error {
	if depth > 64 {
		return fmt.Errorf("canonical JSON nesting exceeds its fixed bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("scan canonical JSON at %s: %w", path, err)
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("scan canonical object at %s: %w", path, err)
			}
			name, ok := nameToken.(string)
			if !ok || name == "" {
				return fmt.Errorf("canonical object name at %s is invalid", path)
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("canonical JSON contains duplicate field %q at %s", name, path)
			}
			seen[name] = struct{}{}
			if err := scanJSONValue(decoder, path+"."+name, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("canonical object at %s is malformed", path)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("canonical array at %s is malformed", path)
		}
	default:
		return fmt.Errorf("canonical JSON at %s has unexpected delimiter", path)
	}
	return nil
}
