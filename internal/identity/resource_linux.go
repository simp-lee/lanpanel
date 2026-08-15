//go:build linux

package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type ResourceAccountSet struct {
	InstallationID string            `json:"installation_id"`
	ResourceID     string            `json:"resource_id"`
	Application    AccountSpec       `json:"application"`
	Relay          *AccountSpec      `json:"relay,omitempty"`
	Identities     []AccountIdentity `json:"identities,omitempty"`
}

func GoAccessAccounts(installationID, resourceID string) (ResourceAccountSet, error) {
	if !ValidateInstallationID(installationID) || len(resourceID) != 36 || !strings.HasPrefix(resourceID, "res_") {
		return ResourceAccountSet{}, fmt.Errorf("GoAccess account authority is invalid")
	}
	digest := sha256.Sum256([]byte(installationID + "\x00" + resourceID))
	suffix := hex.EncodeToString(digest[:])[:20]
	application := AccountSpec{Role: AccountRole("goaccess:" + resourceID), User: "lp-ga-" + suffix, Group: "lp-ga-" + suffix, Comment: "LanPanel " + installationID + " " + resourceID + " GoAccess", Home: LockedHome, Shell: NoLoginShell}
	relay := AccountSpec{Role: AccountRole("goaccess-relay:" + resourceID), User: "lp-gar-" + suffix, Group: "lp-gar-" + suffix, Comment: "LanPanel " + installationID + " " + resourceID + " GoAccess relay", Home: LockedHome, Shell: NoLoginShell}
	set := ResourceAccountSet{InstallationID: installationID, ResourceID: resourceID, Application: application, Relay: &relay}
	return set, validateResourceAccountSet(set, false)
}

func ResourceAccounts(installationID, resourceID string, relay bool) (ResourceAccountSet, error) {
	if !ValidateInstallationID(installationID) || len(resourceID) != 36 || !strings.HasPrefix(resourceID, "res_") {
		return ResourceAccountSet{}, fmt.Errorf("resource account authority is invalid")
	}
	fingerprint, _ := Fingerprint(installationID)
	short := resourceID[4:14]
	prefix := "lp-" + fingerprint[:6] + "-" + short
	application := AccountSpec{Role: AccountRole("app:" + resourceID), User: prefix + "-app", Group: prefix + "-app", Comment: "LanPanel " + installationID + " " + resourceID + " application", Home: LockedHome, Shell: NoLoginShell}
	set := ResourceAccountSet{InstallationID: installationID, ResourceID: resourceID, Application: application}
	if relay {
		value := AccountSpec{Role: AccountRole("relay:" + resourceID), User: prefix + "-relay", Group: prefix + "-relay", Comment: "LanPanel " + installationID + " " + resourceID + " relay", Home: LockedHome, Shell: NoLoginShell}
		set.Relay = &value
	}
	return set, validateResourceAccountSet(set, false)
}

func RenderResourceSysusers(set ResourceAccountSet) ([]byte, error) {
	if err := validateResourceAccountSet(set, false); err != nil {
		return nil, err
	}
	specs := []AccountSpec{set.Application}
	if set.Relay != nil {
		specs = append(specs, *set.Relay)
	}
	var output strings.Builder
	for _, spec := range specs {
		fmt.Fprintf(&output, "g %s - -\n", spec.Group)
		fmt.Fprintf(&output, "u %s -:%s %q %s %s\n", spec.User, spec.Group, spec.Comment, spec.Home, spec.Shell)
	}
	return []byte(output.String()), nil
}

func InspectResourceAccountFiles(set ResourceAccountSet, passwdPath, groupPath, shadowPath string) (bool, []AccountIdentity, error) {
	if err := validateResourceAccountSet(set, false); err != nil {
		return false, nil, err
	}
	specs := []AccountSpec{set.Application}
	if set.Relay != nil {
		specs = append(specs, *set.Relay)
	}
	bootstrapShape := AccountSet{HelperClientGroup: specs[0].Group, Specs: specs}
	// Resource accounts have no shared helper group. The exact database parser
	// is reused with the first group as a synthetic non-member sentinel.
	return inspectResourceAccountFiles(bootstrapShape, set, passwdPath, groupPath, shadowPath)
}

func inspectResourceAccountFiles(_ AccountSet, set ResourceAccountSet, passwdPath, groupPath, shadowPath string) (bool, []AccountIdentity, error) {
	passwdBytes, err := readAccountFile(passwdPath)
	if err != nil {
		return false, nil, err
	}
	groupBytes, err := readAccountFile(groupPath)
	if err != nil {
		return false, nil, err
	}
	shadowBytes, err := readAccountFile(shadowPath)
	if err != nil {
		return false, nil, err
	}
	users, err := parsePasswd(passwdBytes)
	if err != nil {
		return false, nil, err
	}
	groups, err := parseGroups(groupBytes)
	if err != nil {
		return false, nil, err
	}
	shadow, err := parseShadow(shadowBytes)
	if err != nil {
		return false, nil, err
	}
	specs := []AccountSpec{set.Application}
	if set.Relay != nil {
		specs = append(specs, *set.Relay)
	}
	identities := make([]AccountIdentity, 0, len(specs))
	for _, spec := range specs {
		user, userOK := users[spec.User]
		group, groupOK := groups[spec.Group]
		password, shadowOK := shadow[spec.User]
		if !userOK && !groupOK && !shadowOK {
			continue
		}
		if !userOK || !groupOK || !shadowOK || user.uid == 0 || group.gid == 0 || user.gid != group.gid || user.comment != spec.Comment || user.home != spec.Home || user.shell != spec.Shell || len(group.members) != 0 || !lockedPassword(password) {
			return false, nil, fmt.Errorf("resource account %q collides or differs from exact origin", spec.User)
		}
		for name, other := range users {
			if name != spec.User && (other.uid == user.uid || other.gid == group.gid) {
				return false, nil, fmt.Errorf("resource account numeric identity aliases %q", name)
			}
		}
		for name, other := range groups {
			if name != spec.Group && other.gid == group.gid {
				return false, nil, fmt.Errorf("resource group aliases %q", name)
			}
			for _, member := range other.members {
				if member == spec.User {
					return false, nil, fmt.Errorf("resource account %q has supplementary group %q", spec.User, name)
				}
			}
		}
		identities = append(identities, AccountIdentity{Role: spec.Role, User: spec.User, UID: user.uid, Group: spec.Group, GID: group.gid})
	}
	if len(identities) == 0 {
		return false, []AccountIdentity{}, nil
	}
	if len(identities) != len(specs) {
		return false, nil, fmt.Errorf("resource account inventory is partial")
	}
	if len(identities) == 2 && (identities[0].UID == identities[1].UID || identities[0].GID == identities[1].GID) {
		return false, nil, fmt.Errorf("application and relay identities are not distinct")
	}
	return true, identities, nil
}

type AccountDeletionState struct {
	Users  []bool
	Groups []bool
}

func InspectResourceAccountDeletionFiles(set ResourceAccountSet, passwdPath, groupPath, shadowPath string) (AccountDeletionState, error) {
	if err := validateResourceAccountSet(set, true); err != nil {
		return AccountDeletionState{}, err
	}
	passwdBytes, err := readAccountFile(passwdPath)
	if err != nil {
		return AccountDeletionState{}, err
	}
	groupBytes, err := readAccountFile(groupPath)
	if err != nil {
		return AccountDeletionState{}, err
	}
	shadowBytes, err := readAccountFile(shadowPath)
	if err != nil {
		return AccountDeletionState{}, err
	}
	users, err := parsePasswd(passwdBytes)
	if err != nil {
		return AccountDeletionState{}, err
	}
	groups, err := parseGroups(groupBytes)
	if err != nil {
		return AccountDeletionState{}, err
	}
	shadow, err := parseShadow(shadowBytes)
	if err != nil {
		return AccountDeletionState{}, err
	}
	if set.Relay == nil {
		return AccountDeletionState{}, fmt.Errorf("resource deletion relay identity missing")
	}
	specs := []AccountSpec{set.Application, *set.Relay}
	expected := map[string]AccountIdentity{}
	for _, value := range set.Identities {
		expected[value.User] = value
	}
	state := AccountDeletionState{Users: make([]bool, len(specs)), Groups: make([]bool, len(specs))}
	for index, spec := range specs {
		want, ok := expected[spec.User]
		if !ok {
			return AccountDeletionState{}, fmt.Errorf("resource deletion numeric identity missing")
		}
		user, userOK := users[spec.User]
		group, groupOK := groups[spec.Group]
		password, shadowOK := shadow[spec.User]
		if userOK && (!groupOK || user.uid != want.UID || user.gid != want.GID || group.gid != want.GID || user.comment != spec.Comment || user.home != spec.Home || user.shell != spec.Shell) {
			return AccountDeletionState{}, fmt.Errorf("resource deletion user identity differs")
		}
		if shadowOK && !lockedPassword(password) {
			return AccountDeletionState{}, fmt.Errorf("resource deletion shadow identity differs")
		}
		if groupOK && (group.gid != want.GID || len(group.members) != 0) {
			return AccountDeletionState{}, fmt.Errorf("resource deletion group identity differs")
		}
		state.Users[index] = userOK || shadowOK
		state.Groups[index] = groupOK
		for name, other := range users {
			if name != spec.User && (other.uid == want.UID || other.gid == want.GID) {
				return AccountDeletionState{}, fmt.Errorf("resource deletion user identity aliases %q", name)
			}
		}
		for name, other := range groups {
			if name != spec.Group && other.gid == want.GID {
				return AccountDeletionState{}, fmt.Errorf("resource deletion group aliases %q", name)
			}
			for _, member := range other.members {
				if member == spec.User {
					return AccountDeletionState{}, fmt.Errorf("resource deletion account has supplementary group")
				}
			}
		}
	}
	return state, nil
}

func validateResourceAccountSet(set ResourceAccountSet, requireIdentity bool) error {
	if !ValidateInstallationID(set.InstallationID) || len(set.ResourceID) != 36 || !strings.HasPrefix(set.ResourceID, "res_") || set.Application.User == "" || set.Application.Group == "" || set.Application.Home != LockedHome || set.Application.Shell != NoLoginShell || len(set.Application.User) > 31 || len(set.Application.Group) > 31 {
		return fmt.Errorf("resource account set is invalid")
	}
	if set.Relay != nil && (set.Relay.User == set.Application.User || set.Relay.Group == set.Application.Group || set.Relay.Home != LockedHome || set.Relay.Shell != NoLoginShell) {
		return fmt.Errorf("resource relay account is not distinct and locked")
	}
	if requireIdentity && len(set.Identities) == 0 {
		return fmt.Errorf("resource numeric identities are absent")
	}
	return nil
}
