package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const MaxInstallationDocumentBytes = 16 << 20

func DecodeInstallation(data []byte) (Installation, error) {
	if len(data) == 0 {
		return Installation{}, fmt.Errorf("installation document is empty")
	}
	if len(data) > MaxInstallationDocumentBytes {
		return Installation{}, fmt.Errorf("installation document exceeds %d bytes", MaxInstallationDocumentBytes)
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return Installation{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var installation Installation
	if err := decoder.Decode(&installation); err != nil {
		return Installation{}, fmt.Errorf("decode installation document: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return Installation{}, fmt.Errorf("decode installation document suffix: %w", err)
		}
		return Installation{}, fmt.Errorf("installation document contains another JSON value beginning with %v", token)
	}
	if err := ValidateInstallation(installation); err != nil {
		return Installation{}, fmt.Errorf("validate installation document: %w", err)
	}
	return installation, nil
}

func rejectDuplicateJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder, "$"); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("scan installation document suffix: %w", err)
		}
		return fmt.Errorf("installation document contains another JSON value beginning with %v", token)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("scan installation document at %s: %w", path, err)
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
				return fmt.Errorf("scan installation object at %s: %w", path, err)
			}
			name, ok := nameToken.(string)
			if !ok {
				return fmt.Errorf("scan installation object at %s: object name is not a string", path)
			}
			if !canonicalJSONName(name) {
				return fmt.Errorf("installation document contains non-canonical field %q at %s", name, path)
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("installation document contains duplicate field %q at %s", name, path)
			}
			seen[name] = struct{}{}
			if err := scanJSONValue(decoder, path+"."+name); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("scan installation object at %s: malformed closing delimiter", path)
		}
		return nil
	case '[':
		index := 0
		for decoder.More() {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
			index++
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("scan installation array at %s: malformed closing delimiter", path)
		}
		return nil
	default:
		return fmt.Errorf("scan installation document at %s: unexpected delimiter %q", path, delimiter)
	}
}

func canonicalJSONName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
