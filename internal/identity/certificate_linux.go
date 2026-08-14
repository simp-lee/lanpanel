//go:build linux

package identity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

const certificateNumericBase uint32 = 2_000_000

type CertificateStageIdentity struct {
	CertificateID string
	UID           uint32
	GID           uint32
}

func CertificateStageIdentityFor(certificateID string) (CertificateStageIdentity, error) {
	if len(certificateID) != 37 || !strings.HasPrefix(certificateID, "cert_") {
		return CertificateStageIdentity{}, fmt.Errorf("certificate stage identity invalid")
	}
	raw, err := hex.DecodeString(certificateID[5:])
	if err != nil || len(raw) != 16 {
		return CertificateStageIdentity{}, fmt.Errorf("certificate stage identity invalid")
	}
	numeric := certificateNumericBase + (uint32(raw[0]) << 16) + (uint32(raw[1]) << 8) + uint32(raw[2])
	return CertificateStageIdentity{CertificateID: certificateID, UID: numeric, GID: numeric}, nil
}

// VerifyCertificateStageIdentityAvailable proves that the ephemeral numeric
// identity cannot alias a persistent host account. The certificate journal is
// the origin authority; no passwd/group entry is created for this bounded child.
func VerifyCertificateStageIdentityAvailable(stage CertificateStageIdentity, passwdPath, groupPath string) error {
	expected, err := CertificateStageIdentityFor(stage.CertificateID)
	if err != nil || stage != expected {
		return fmt.Errorf("certificate stage authority changed")
	}
	passwdBytes, err := readAccountFile(passwdPath)
	if err != nil {
		return err
	}
	groupBytes, err := readAccountFile(groupPath)
	if err != nil {
		return err
	}
	users, err := parsePasswd(passwdBytes)
	if err != nil {
		return err
	}
	groups, err := parseGroups(groupBytes)
	if err != nil {
		return err
	}
	for name, user := range users {
		if user.uid == stage.UID || user.gid == stage.GID {
			return fmt.Errorf("certificate stage numeric identity collides with user %q", name)
		}
	}
	for name, group := range groups {
		if group.gid == stage.GID {
			return fmt.Errorf("certificate stage numeric identity collides with group %q", name)
		}
	}
	if account, lookupErr := user.LookupId(strconv.FormatUint(uint64(stage.UID), 10)); lookupErr == nil {
		return fmt.Errorf("certificate stage numeric identity collides with NSS user %q", account.Username)
	} else {
		var unknown user.UnknownUserIdError
		if !errors.As(lookupErr, &unknown) {
			return fmt.Errorf("certificate stage NSS user inventory unavailable: %w", lookupErr)
		}
	}
	if group, lookupErr := user.LookupGroupId(strconv.FormatUint(uint64(stage.GID), 10)); lookupErr == nil {
		return fmt.Errorf("certificate stage numeric identity collides with NSS group %q", group.Name)
	} else {
		var unknown user.UnknownGroupIdError
		if !errors.As(lookupErr, &unknown) {
			return fmt.Errorf("certificate stage NSS group inventory unavailable: %w", lookupErr)
		}
	}
	return nil
}
