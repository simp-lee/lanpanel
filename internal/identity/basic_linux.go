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

const htpasswdNumericBase uint32 = 30_000_000

type EphemeralHTPasswdIdentity struct {
	CredentialID string
	UID          uint32
	GID          uint32
}

func EphemeralHTPasswdIdentityFor(credentialID string) (EphemeralHTPasswdIdentity, error) {
	if len(credentialID) != 37 || !strings.HasPrefix(credentialID, "cred_") {
		return EphemeralHTPasswdIdentity{}, fmt.Errorf("htpasswd identity invalid")
	}
	raw, err := hex.DecodeString(credentialID[5:])
	if err != nil || len(raw) != 16 {
		return EphemeralHTPasswdIdentity{}, fmt.Errorf("htpasswd identity invalid")
	}
	numeric := htpasswdNumericBase + (uint32(raw[0]) << 16) + (uint32(raw[1]) << 8) + uint32(raw[2])
	return EphemeralHTPasswdIdentity{CredentialID: credentialID, UID: numeric, GID: numeric}, nil
}

func VerifyEphemeralHTPasswdIdentityAvailable(value EphemeralHTPasswdIdentity, passwdPath, groupPath string) error {
	expected, err := EphemeralHTPasswdIdentityFor(value.CredentialID)
	if err != nil || value != expected {
		return fmt.Errorf("htpasswd identity authority changed")
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
	for name, entry := range users {
		if entry.uid == value.UID || entry.gid == value.GID {
			return fmt.Errorf("htpasswd numeric identity collides with user %q", name)
		}
	}
	for name, entry := range groups {
		if entry.gid == value.GID {
			return fmt.Errorf("htpasswd numeric identity collides with group %q", name)
		}
	}
	if account, lookupErr := user.LookupId(strconv.FormatUint(uint64(value.UID), 10)); lookupErr == nil {
		return fmt.Errorf("htpasswd numeric identity collides with NSS user %q", account.Username)
	} else {
		var unknown user.UnknownUserIdError
		if !errors.As(lookupErr, &unknown) {
			return fmt.Errorf("htpasswd NSS user inventory unavailable: %w", lookupErr)
		}
	}
	if group, lookupErr := user.LookupGroupId(strconv.FormatUint(uint64(value.GID), 10)); lookupErr == nil {
		return fmt.Errorf("htpasswd numeric identity collides with NSS group %q", group.Name)
	} else {
		var unknown user.UnknownGroupIdError
		if !errors.As(lookupErr, &unknown) {
			return fmt.Errorf("htpasswd NSS group inventory unavailable: %w", lookupErr)
		}
	}
	return nil
}
