//go:build linux

package identity

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	LockedHome                  = "/nonexistent"
	NoLoginShell                = "/usr/sbin/nologin"
	maximumAccountDatabaseBytes = 4 << 20
)

type AccountRole string

const (
	RoleUI        AccountRole = "ui"
	RoleTimer     AccountRole = "timer"
	RoleRecovery  AccountRole = "recovery"
	RoleHeadscale AccountRole = "headscale"
	RoleHTPasswd  AccountRole = "htpasswd"
	RoleTailscale AccountRole = "tailscale"
)

type AccountSpec struct {
	Role    AccountRole `json:"role"`
	User    string      `json:"user"`
	Group   string      `json:"group"`
	Comment string      `json:"comment"`
	Home    string      `json:"home"`
	Shell   string      `json:"shell"`
}

type AccountIdentity struct {
	Role  AccountRole `json:"role"`
	User  string      `json:"user"`
	UID   uint32      `json:"uid"`
	Group string      `json:"group"`
	GID   uint32      `json:"gid"`
}

type AccountSet struct {
	HelperClientGroup string            `json:"helper_client_group"`
	Specs             []AccountSpec     `json:"specs"`
	Identities        []AccountIdentity `json:"identities"`
}

func InstallationAccounts(installationID string) (AccountSet, error) {
	fingerprint, err := Fingerprint(installationID)
	if err != nil {
		return AccountSet{}, err
	}
	prefix := "lp-" + fingerprint[:10]
	clientGroup := prefix + "-clients"
	roles := []struct {
		role   AccountRole
		suffix string
	}{{RoleUI, "ui"}, {RoleTimer, "timer"}, {RoleRecovery, "recovery"}, {RoleHTPasswd, "htp"}, {RoleTailscale, "tailscale"}}
	set := AccountSet{HelperClientGroup: clientGroup, Specs: make([]AccountSpec, 0, len(roles))}
	for _, value := range roles {
		name := prefix + "-" + value.suffix
		group := name
		if value.role == RoleUI || value.role == RoleTimer || value.role == RoleRecovery {
			group = clientGroup
		}
		set.Specs = append(set.Specs, AccountSpec{Role: value.role, User: name, Group: group, Comment: "LanPanel " + installationID + " " + string(value.role), Home: LockedHome, Shell: NoLoginShell})
	}
	return set, nil
}

func HeadscaleAccounts(installationID, headscaleID string) (AccountSet, error) {
	fingerprint, err := Fingerprint(installationID)
	if err != nil || !regexp.MustCompile(`^hds_[0-9a-f]{32}$`).MatchString(headscaleID) {
		return AccountSet{}, fmt.Errorf("headscale account identity is invalid")
	}
	prefix := "lp-" + fingerprint[:10]
	name := prefix + "-headscale"
	return AccountSet{HelperClientGroup: prefix + "-clients", Specs: []AccountSpec{{Role: RoleHeadscale, User: name, Group: name, Comment: "LanPanel " + installationID + " headscale " + headscaleID, Home: LockedHome, Shell: NoLoginShell}}}, nil
}

func RenderSysusers(set AccountSet) ([]byte, error) {
	if err := validateAccountSet(set, false); err != nil {
		return nil, err
	}
	var output strings.Builder
	fmt.Fprintf(&output, "g %s - -\n", set.HelperClientGroup)
	createdGroups := map[string]bool{set.HelperClientGroup: true}
	for _, spec := range set.Specs {
		if !createdGroups[spec.Group] {
			fmt.Fprintf(&output, "g %s - -\n", spec.Group)
			createdGroups[spec.Group] = true
		}
		fmt.Fprintf(&output, "u %s -:%s %q %s %s\n", spec.User, spec.Group, spec.Comment, spec.Home, spec.Shell)
	}
	return []byte(output.String()), nil
}

// InspectAccounts rejects every partial or colliding account inventory. It
// returns present=false only when every installation-specific name is absent.
func InspectAccounts(set AccountSet) (present bool, identities []AccountIdentity, err error) {
	return inspectAccountFiles(set, "/etc/passwd", "/etc/group", "/etc/shadow", false)
}

// InspectPartialAccounts accepts only an exact subset created from the same
// installation sysusers specification. It is used solely to resume a submitted
// bootstrap account transaction before rerunning the same fixed child.
func InspectPartialAccounts(set AccountSet) (complete bool, identities []AccountIdentity, err error) {
	return inspectAccountFiles(set, "/etc/passwd", "/etc/group", "/etc/shadow", true)
}

func PartialAccountEvidencePresent(set AccountSet) (bool, error) {
	if err := validateAccountSet(set, false); err != nil {
		return false, err
	}
	passwdBytes, err := readAccountFile("/etc/passwd")
	if err != nil {
		return false, err
	}
	groupBytes, err := readAccountFile("/etc/group")
	if err != nil {
		return false, err
	}
	shadowBytes, err := readAccountFile("/etc/shadow")
	if err != nil {
		return false, err
	}
	users, err := parsePasswd(passwdBytes)
	if err != nil {
		return false, err
	}
	groups, err := parseGroups(groupBytes)
	if err != nil {
		return false, err
	}
	shadow, err := parseShadow(shadowBytes)
	if err != nil {
		return false, err
	}
	for _, spec := range set.Specs {
		if _, present := users[spec.User]; present {
			return true, nil
		}
		if _, present := groups[spec.Group]; present {
			return true, nil
		}
		if _, present := shadow[spec.User]; present {
			return true, nil
		}
	}
	return false, nil
}

func InspectAccountFiles(set AccountSet, passwdPath, groupPath, shadowPath string) (bool, []AccountIdentity, error) {
	return inspectAccountFiles(set, passwdPath, groupPath, shadowPath, false)
}

func inspectAccountFiles(set AccountSet, passwdPath, groupPath, shadowPath string, allowPartial bool) (bool, []AccountIdentity, error) {
	if err := validateAccountSet(set, false); err != nil {
		return false, nil, err
	}
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
	identities := make([]AccountIdentity, 0, len(set.Specs))
	client, clientExists := groups[set.HelperClientGroup]
	foundAny := false
	if clientExists {
		if len(client.members) != 0 || client.gid == 0 {
			return false, nil, fmt.Errorf("helper client group is unsafe")
		}
	}
	seenUID := map[uint32]bool{}
	installationUsers := map[string]bool{}
	for _, spec := range set.Specs {
		installationUsers[spec.User] = true
	}
	for _, spec := range set.Specs {
		user, userExists := users[spec.User]
		group, groupExists := groups[spec.Group]
		password, shadowExists := shadow[spec.User]
		foundAny = foundAny || userExists || groupExists || shadowExists
		if !userExists && !groupExists && !shadowExists {
			continue
		}
		if !clientExists {
			return false, nil, fmt.Errorf("installation helper client group is missing")
		}
		if allowPartial {
			if groupExists && (group.gid == 0 || len(group.members) != 0) {
				return false, nil, fmt.Errorf("partial installation group %q is unsafe", spec.Group)
			}
			if userExists && (user.uid == 0 || user.comment != spec.Comment || user.home != spec.Home || user.shell != spec.Shell) {
				return false, nil, fmt.Errorf("partial installation user %q is unsafe", spec.User)
			}
			if shadowExists && !lockedPassword(password) {
				return false, nil, fmt.Errorf("partial installation user %q is not locked", spec.User)
			}
			if userExists && groupExists && user.gid != group.gid {
				return false, nil, fmt.Errorf("partial installation user/group identity mismatched")
			}
			if !userExists || !groupExists || !shadowExists {
				continue
			}
		}
		if !userExists || !groupExists || !shadowExists || user.uid == 0 || user.gid != group.gid || group.gid == 0 || user.comment != spec.Comment || user.home != spec.Home || user.shell != spec.Shell || len(group.members) != 0 || !lockedPassword(password) || seenUID[user.uid] {
			return false, nil, fmt.Errorf("installation account %q collides or differs from its exact origin", spec.User)
		}
		for name, other := range users {
			if name != spec.User && other.uid == user.uid {
				return false, nil, fmt.Errorf("installation UID %d aliases foreign user %q", user.uid, name)
			}
			if !installationUsers[name] && other.gid == group.gid {
				return false, nil, fmt.Errorf("installation GID %d is primary for foreign user %q", group.gid, name)
			}
		}
		for name, other := range groups {
			if name != spec.Group && other.gid == group.gid {
				return false, nil, fmt.Errorf("installation GID %d aliases foreign group %q", group.gid, name)
			}
		}
		seenUID[user.uid] = true
		identities = append(identities, AccountIdentity{Role: spec.Role, User: spec.User, UID: user.uid, Group: spec.Group, GID: group.gid})
	}
	if !foundAny {
		return false, []AccountIdentity{}, nil
	}
	if len(identities) != len(set.Specs) {
		if allowPartial {
			return false, identities, nil
		}
		return false, nil, fmt.Errorf("installation account inventory is partial")
	}
	for _, group := range groups {
		for _, member := range group.members {
			for _, spec := range set.Specs {
				if member == spec.User {
					return false, nil, fmt.Errorf("installation account %q has supplementary group membership", member)
				}
			}
		}
	}
	slices.SortFunc(identities, func(left, right AccountIdentity) int { return strings.Compare(string(left.Role), string(right.Role)) })
	return true, identities, validateAccountSet(AccountSet{HelperClientGroup: set.HelperClientGroup, Specs: set.Specs, Identities: identities}, true)
}

func IdentityFor(set AccountSet, role AccountRole) (AccountIdentity, bool) {
	for _, value := range set.Identities {
		if value.Role == role {
			return value, true
		}
	}
	return AccountIdentity{}, false
}

type passwdEntry struct {
	uid, gid             uint32
	comment, home, shell string
}
type groupEntry struct {
	gid     uint32
	members []string
}

func parsePasswd(data []byte) (map[string]passwdEntry, error) {
	result := map[string]passwdEntry{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 7 || fields[0] == "" {
			return nil, fmt.Errorf("passwd database is malformed")
		}
		uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
		gid, gidErr := strconv.ParseUint(fields[3], 10, 32)
		if uidErr != nil || gidErr != nil {
			return nil, fmt.Errorf("passwd numeric identity is malformed")
		}
		if _, duplicate := result[fields[0]]; duplicate {
			return nil, fmt.Errorf("passwd database duplicates a user")
		}
		result[fields[0]] = passwdEntry{uint32(uid), uint32(gid), fields[4], fields[5], fields[6]}
	}
	return result, scanner.Err()
}

func parseGroups(data []byte) (map[string]groupEntry, error) {
	result := map[string]groupEntry{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 4 || fields[0] == "" {
			return nil, fmt.Errorf("group database is malformed")
		}
		gid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("group numeric identity is malformed")
		}
		members := []string{}
		if fields[3] != "" {
			members = strings.Split(fields[3], ",")
		}
		if _, duplicate := result[fields[0]]; duplicate {
			return nil, fmt.Errorf("group database duplicates a group")
		}
		result[fields[0]] = groupEntry{uint32(gid), members}
	}
	return result, scanner.Err()
}

func parseShadow(data []byte) (map[string]string, error) {
	result := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 2 || fields[0] == "" {
			return nil, fmt.Errorf("shadow database is malformed")
		}
		if _, duplicate := result[fields[0]]; duplicate {
			return nil, fmt.Errorf("shadow database duplicates a user")
		}
		result[fields[0]] = fields[1]
	}
	return result, scanner.Err()
}

func lockedPassword(value string) bool {
	return value == "!" || strings.HasPrefix(value, "!!") || strings.HasPrefix(value, "!*") || value == "*"
}

func readAccountFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("account database path is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("account database descriptor is invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != 0 && before.Uid != uint32(os.Geteuid()) || before.Mode&0o022 != 0 || before.Size < 0 || before.Size > maximumAccountDatabaseBytes {
		return nil, fmt.Errorf("account database type, owner, mode, link, or size is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumAccountDatabaseBytes+1))
	if err != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim {
		return nil, fmt.Errorf("account database changed during inspection")
	}
	return data, nil
}

func validateAccountSet(set AccountSet, requireIdentities bool) error {
	if set.HelperClientGroup == "" || len(set.HelperClientGroup) > 31 || len(set.Specs) == 0 || len(set.Specs) > 6 || requireIdentities && len(set.Identities) != len(set.Specs) {
		return fmt.Errorf("installation account set is incomplete")
	}
	seenRole, seenName := map[AccountRole]bool{}, map[string]bool{}
	for _, spec := range set.Specs {
		if spec.Role == "" || spec.User == "" || len(spec.User) > 31 || spec.Group == "" || len(spec.Group) > 31 || spec.Comment == "" || spec.Home != LockedHome || spec.Shell != NoLoginShell || strings.ContainsAny(spec.User+spec.Group, "\x00\r\n :\t") || strings.ContainsAny(spec.Comment, "\x00\r\n:") || seenRole[spec.Role] || seenName[spec.User] {
			return fmt.Errorf("installation account specification is invalid or duplicated")
		}
		seenRole[spec.Role], seenName[spec.User] = true, true
	}
	installationSet := len(set.Specs) == 5 && seenRole[RoleUI] && seenRole[RoleTimer] && seenRole[RoleRecovery] && seenRole[RoleHTPasswd] && seenRole[RoleTailscale]
	headscaleSet := len(set.Specs) == 1 && seenRole[RoleHeadscale]
	if !installationSet && !headscaleSet {
		return fmt.Errorf("account set role closure is invalid")
	}
	if requireIdentities {
		for _, value := range set.Identities {
			if value.Role == "" || value.User == "" || value.UID == 0 || value.Group == "" || value.GID == 0 {
				return fmt.Errorf("installation numeric account identity is invalid")
			}
		}
	}
	return nil
}

var _ = errors.Is
