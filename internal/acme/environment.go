package acme

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
)

const EnvironmentFrameSchema = "lanpanel.acme.environment.v1"

func BuildEnvironment(binding Binding) ([]string, error) {
	if err := ValidateBinding(binding); err != nil {
		return nil, err
	}
	if current, err := fingerprintProtected(binding.AccountKeyPath); err != nil || current != binding.AccountKeyFingerprint {
		return nil, fmt.Errorf("ACME account binding changed")
	}
	environment := []string{"LANG=C", "LC_ALL=C"}
	if binding.Method == ChallengeHTTP01 {
		return environment, nil
	}
	if current, err := fingerprintProtected(binding.ProfilePath); err != nil || current != binding.ProfileFingerprint {
		return nil, fmt.Errorf("DNS profile binding changed")
	}
	values, err := parseProfile(binding.ProfilePath)
	if err != nil {
		return nil, err
	}
	if binding.Provider == DNSProviderRoute53 {
		if err := validateRoute53Credentials(values["AWS_SHARED_CREDENTIALS_FILE"], values["AWS_PROFILE"]); err != nil {
			return nil, err
		}
	}
	if binding.Provider == DNSProviderGCloud {
		if err := validateGCloudCredentials(values["GCE_SERVICE_ACCOUNT_FILE"], values["GCE_PROJECT"]); err != nil {
			return nil, err
		}
	}
	files := map[string]CredentialFile{}
	for _, file := range binding.CredentialFiles {
		files[file.Key] = file
	}
	for key, value := range values {
		file, present := files[key]
		if present {
			if value != file.Path {
				return nil, fmt.Errorf("DNS credential path changed")
			}
			current, err := fingerprintProtected(file.Path)
			if err != nil || current != file.Fingerprint {
				return nil, fmt.Errorf("DNS credential binding changed")
			}
			environment = append(environment, key+"="+file.Path)
			continue
		}
		if !strings.Contains(binding.Principal, key+"="+value+";") {
			return nil, fmt.Errorf("DNS principal identity changed")
		}
		environment = append(environment, key+"="+value)
	}
	if binding.Provider == DNSProviderRoute53 {
		environment = append(environment, "AWS_EC2_METADATA_DISABLED=true")
	}
	slices.Sort(environment[2:])
	return environment, nil
}
func EncodeEnvironmentFrame(environment []string) ([]byte, error) {
	if len(environment) < 2 || len(environment) > 32 {
		return nil, fmt.Errorf("ACME environment invalid")
	}
	var output bytes.Buffer
	output.WriteString(EnvironmentFrameSchema + "\x00")
	for _, value := range environment {
		if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") || !strings.Contains(value, "=") {
			return nil, fmt.Errorf("ACME environment invalid")
		}
		output.WriteString(value)
		output.WriteByte(0)
	}
	if output.Len() > 64<<10 {
		return nil, fmt.Errorf("ACME environment oversized")
	}
	return output.Bytes(), nil
}
func DecodeEnvironmentFrame(reader io.Reader) ([]string, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, 64<<10+1))
	if err != nil || len(payload) > 64<<10 {
		return nil, fmt.Errorf("ACME environment frame invalid")
	}
	parts := bytes.Split(payload, []byte{0})
	if len(parts) < 4 || string(parts[0]) != EnvironmentFrameSchema || len(parts[len(parts)-1]) != 0 {
		return nil, fmt.Errorf("ACME environment frame invalid")
	}
	environment := make([]string, len(parts)-2)
	seen := map[string]bool{}
	for index, value := range parts[1 : len(parts)-1] {
		environment[index] = string(value)
		key, _, found := strings.Cut(environment[index], "=")
		if !found || key == "" || seen[key] || strings.ContainsAny(environment[index], "\x00\r\n") {
			return nil, fmt.Errorf("ACME environment frame invalid")
		}
		seen[key] = true
	}
	return environment, nil
}
