// Package identity creates and validates installation-scoped bootstrap identities.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"regexp"
)

const (
	AdminTokenRandomBytes = 32
	attemptRandomBytes    = 32
	installationBytes     = 16
	generationBytes       = 16
	managementPortBase    = 49152
	managementPortCount   = 16384
)

type ManagementAuthority struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type Material struct {
	AttemptID        string
	InstallationID   string
	GenerationID     string
	SafetyGeneration uint64
	Authority        ManagementAuthority
	token            []byte
}

// Generate obtains every fresh-install random value before the caller performs
// a side effect. Production callers pass crypto/rand.Reader.
func Generate(reader io.Reader) (Material, error) {
	if reader == nil {
		reader = rand.Reader
	}
	attempt, err := randomHex(reader, attemptRandomBytes)
	if err != nil {
		return Material{}, fmt.Errorf("generate bootstrap attempt identity: %w", err)
	}
	installation, err := randomHex(reader, installationBytes)
	if err != nil {
		return Material{}, fmt.Errorf("generate installation identity: %w", err)
	}
	generationRaw := make([]byte, generationBytes)
	if _, err := io.ReadFull(reader, generationRaw); err != nil {
		clear(generationRaw)
		return Material{}, fmt.Errorf("generate installation generation: %w", err)
	}
	allZero := true
	for _, value := range generationRaw[:8] {
		allZero = allZero && value == 0
	}
	if allZero {
		generationRaw[7] = 1
	}
	generation := hex.EncodeToString(generationRaw)
	safetyGeneration := uint64(0)
	for _, value := range generationRaw[:8] {
		safetyGeneration = safetyGeneration<<8 | uint64(value)
	}
	clear(generationRaw)
	authority, err := GenerateManagementAuthority(reader)
	if err != nil {
		return Material{}, err
	}
	token := make([]byte, AdminTokenRandomBytes)
	if _, err := io.ReadFull(reader, token); err != nil {
		clear(token)
		return Material{}, fmt.Errorf("generate admin token: %w", err)
	}
	return Material{
		AttemptID: "bst_" + attempt, InstallationID: "ins_" + installation,
		GenerationID: "gen_" + generation, SafetyGeneration: safetyGeneration, Authority: authority, token: token,
	}, nil
}

// GenerateAdminToken is used only when an exact uncommitted bootstrap attempt
// has no staged or committed bundle. It never falls back to another source.
func GenerateAdminToken(reader io.Reader) ([]byte, error) {
	if reader == nil {
		reader = rand.Reader
	}
	raw := make([]byte, AdminTokenRandomBytes)
	if _, err := io.ReadFull(reader, raw); err != nil {
		clear(raw)
		return nil, fmt.Errorf("generate admin token: %w", err)
	}
	encoded := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(encoded, raw)
	clear(raw)
	return encoded, nil
}

func (material *Material) TakeAdminToken() []byte {
	if material == nil || len(material.token) != AdminTokenRandomBytes {
		return nil
	}
	encoded := make([]byte, hex.EncodedLen(len(material.token)))
	hex.Encode(encoded, material.token)
	clear(material.token)
	material.token = nil
	return encoded
}

func (material *Material) Destroy() {
	if material == nil {
		return
	}
	clear(material.token)
	material.token = nil
}

// GenerateManagementAuthority uniformly selects 24 address bits and 14 high
// port bits. The resulting authority therefore has exactly 38 random bits.
func GenerateManagementAuthority(reader io.Reader) (ManagementAuthority, error) {
	if reader == nil {
		reader = rand.Reader
	}
	var value [5]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return ManagementAuthority{}, fmt.Errorf("generate Management authority: %w", err)
	}
	address := netip.AddrFrom4([4]byte{127, value[0], value[1], value[2]})
	portBits := uint16(value[3])<<8 | uint16(value[4])
	port := uint16(managementPortBase + int(portBits&(managementPortCount-1)))
	authority := ManagementAuthority{Address: address.String(), Port: port}
	if err := ValidateManagementAuthority(authority); err != nil {
		return ManagementAuthority{}, err
	}
	return authority, nil
}

func ValidateManagementAuthority(authority ManagementAuthority) error {
	address, err := netip.ParseAddr(authority.Address)
	if err != nil || !address.Is4() || !address.IsLoopback() || address.IsUnspecified() || address.String() != authority.Address || authority.Port < managementPortBase {
		return fmt.Errorf("management authority is not an exact random 127/8 literal and high port")
	}
	return nil
}

var (
	attemptPattern      = regexp.MustCompile(`^bst_[0-9a-f]{64}$`)
	installationPattern = regexp.MustCompile(`^ins_[0-9a-f]{32}$`)
	generationPattern   = regexp.MustCompile(`^gen_[0-9a-f]{32}$`)
)

func ValidateAttemptID(value string) bool      { return attemptPattern.MatchString(value) }
func ValidateInstallationID(value string) bool { return installationPattern.MatchString(value) }
func ValidateGenerationID(value string) bool   { return generationPattern.MatchString(value) }

func Fingerprint(installationID string) (string, error) {
	if !ValidateInstallationID(installationID) {
		return "", fmt.Errorf("installation identity is invalid")
	}
	digest := sha256.Sum256([]byte(installationID))
	return hex.EncodeToString(digest[:8]), nil
}

func randomHex(reader io.Reader, bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := io.ReadFull(reader, value); err != nil {
		clear(value)
		return "", err
	}
	encoded := hex.EncodeToString(value)
	clear(value)
	return encoded, nil
}
