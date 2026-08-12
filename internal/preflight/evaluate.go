package preflight

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

func EvaluateExpansion(request ExpansionRequest, observed ExpansionObservations) (Result, error) {
	if err := validateExpansionRequest(request); err != nil {
		return Result{}, err
	}
	if observed.Clock.Now.IsZero() {
		return Result{}, fmt.Errorf("preflight observation time is required")
	}
	if !slices.EqualFunc(observed.DNS, canonicalDNS(observed.DNS), func(left, right DNSObservation) bool {
		return left.Domain == right.Domain && slices.Equal(left.Addresses, right.Addresses) && left.Failure == right.Failure
	}) {
		return Result{}, fmt.Errorf("DNS observations are noncanonical")
	}
	requestDigest, err := ExpansionRequestDigest(request)
	if err != nil {
		return Result{}, err
	}
	findings := []Finding{}
	add := func(code string, passed bool, summary, identity string) {
		disposition := FindingPassed
		if !passed {
			disposition = FindingBlocked
		}
		findings = append(findings, Finding{Code: code, Disposition: disposition, Summary: summary, Identity: identity})
	}
	add("architecture", observed.OperatingSystem == "linux" && observed.Architecture == request.Profile.Architecture && observed.Architecture == "amd64", "exact Linux amd64 architecture", observed.OperatingSystem+"/"+observed.Architecture)
	profileMatches := observed.Platform.ID == request.Profile.ID && observed.Platform.VersionID == request.Profile.VersionID && validProfileAuthority(request.Profile)
	add("os_profile", profileMatches, "exact authorized OS profile", observed.Platform.ID+"/"+observed.Platform.VersionID+"/"+request.Profile.Authority.Digest)
	clockOK := !request.LastTrustedWall.IsZero() && observed.Clock.Synchronized && !observed.Clock.Now.Before(request.LastTrustedWall)
	add("trusted_clock", clockOK, "trusted synchronized wall clock without regression", observed.Clock.Source+"/"+observed.Clock.Now.UTC().Format(time.RFC3339Nano))
	add("root_executor", observed.ExecutorUID == 0, "actual mutation executor is root", strconv.FormatUint(uint64(observed.ExecutorUID), 10))
	add("systemd", observed.Systemd.Available && observed.Systemd.Identity != "", "systemd runtime and identity", observed.Systemd.Identity)
	add("apt", observed.APT.Available && observed.APT.Identity != "", "apt capability and identity", observed.APT.Identity)
	add("dpkg", observed.DPKG.Available && observed.DPKG.Identity != "", "dpkg capability and identity", observed.DPKG.Identity)
	packageExact := observed.Packages.Ready && observed.Packages.Identity != "" && observed.Packages.SystemdVersion == request.Profile.SystemdVersion && observed.Packages.NginxVersion == request.Profile.NginxVersion && observed.Packages.PackageSnapshotDigest == request.Profile.PackageSnapshotDigest
	add("package_state", packageExact, "apt/dpkg state and exact release package profile are ready", observed.Packages.Identity+"/"+observed.Packages.SystemdVersion+"/"+observed.Packages.NginxVersion+"/"+observed.Packages.PackageSnapshotDigest+"/"+observed.Packages.Reason)

	if len(observed.DNS) != len(request.Domains) {
		add("dns", false, "complete exact DNS observations", fmt.Sprintf("observed=%d/required=%d", len(observed.DNS), len(request.Domains)))
	} else if len(request.Domains) == 0 {
		add("dns", true, "exact public DNS observations", "not_applicable")
	} else {
		dnsOK, identities := true, []string{}
		for index, domain := range request.Domains {
			observation := observed.DNS[index]
			if observation.Domain != domain || observation.Failure != "" || len(observation.Addresses) == 0 || !canonicalStringSet(observation.Addresses, canonicalIP) {
				dnsOK = false
			}
			identities = append(identities, observation.Domain+"="+strings.Join(observation.Addresses, ",")+"/"+observation.Failure)
		}
		add("dns", dnsOK, "exact public DNS observations", strings.Join(identities, ";"))
	}

	requirements := requiredListeners(request)
	listenersOK, listenerIdentity := validateListenerObservations(requirements, request.OwnedListeners, observed.Listeners, observed.ListenerInventoryComplete)
	add("listeners", listenersOK, "exact required listener conflict inventory", listenerIdentity)

	pathsOK, pathIdentity := validatePathObservations(request.ManagedPaths, observed.Paths)
	add("managed_paths", pathsOK, "managed path ownership and permission inventory", pathIdentity)
	disksOK, diskIdentity := validateDiskObservations(request.Disks, observed.Disks)
	add("disk", disksOK, "managed filesystem free-space inventory", diskIdentity)

	for _, responsibility := range publicResponsibilities(request) {
		findings = append(findings, responsibility)
	}
	return newResult(string(request.Scope), request.Target, request.Generation, requestDigest, observed.Clock.Now, findings)
}

func EvaluateContraction(request ContractionRequest, observed ContractionObservations) (Result, error) {
	if err := validateContractionRequest(request); err != nil {
		return Result{}, err
	}
	if observed.ObservedAt.IsZero() || len(observed.Diagnostics) > MaximumDiagnostics || len(observed.OwnedIngress) > MaximumOwnedIngress {
		return Result{}, fmt.Errorf("contraction observation time or bounds are invalid")
	}
	requestDigest, err := ContractionRequestDigest(request)
	if err != nil {
		return Result{}, err
	}
	findings := []Finding{}
	add := func(code string, passed bool, summary, identity string) {
		disposition := FindingPassed
		if !passed {
			disposition = FindingBlocked
		}
		findings = append(findings, Finding{Code: code, Disposition: disposition, Summary: summary, Identity: identity})
	}
	add("closure_authority", observed.ClosureAuthorityDigest == request.ClosureAuthorityDigest, "exact closure authority", observed.ClosureAuthorityDigest)
	ownedExact := observed.InventoryComplete && observed.OwnershipInventoryDigest == request.OwnershipInventoryDigest && slices.Equal(observed.OwnedIngress, request.OwnedIngress)
	if request.FallbackStop {
		add("owned_ingress", true, "fallback stop does not narrow uncertain owned-ingress inventory", observed.OwnershipInventoryDigest)
	} else {
		add("owned_ingress", ownedExact, "complete exact owned-ingress inventory", observed.OwnershipInventoryDigest)
	}
	add("root_executor", observed.ExecutorUID == 0, "actual contraction executor is root", strconv.FormatUint(uint64(observed.ExecutorUID), 10))
	for _, diagnostic := range observed.Diagnostics {
		if validDiagnostic(diagnostic) {
			findings = append(findings, Finding{Code: "diagnostic/" + diagnostic.Code, Disposition: FindingDiagnostic, Summary: diagnostic.Summary, Identity: diagnostic.Identity})
		}
	}
	return newResult(string(request.Kind), request.Target, request.Generation, requestDigest, observed.ObservedAt, findings)
}

func canonicalDNS(values []DNSObservation) []DNSObservation {
	result := append([]DNSObservation(nil), values...)
	slices.SortFunc(result, func(left, right DNSObservation) int { return strings.Compare(left.Domain, right.Domain) })
	return result
}

func validateExpansionRequest(request ExpansionRequest) error {
	if !validExpansionScope(request.Scope) || !validTarget(request.Target) || request.Generation == 0 || request.Profile.Architecture != "amd64" || !refPattern.MatchString(request.Profile.SystemdVersion) || !refPattern.MatchString(request.Profile.NginxVersion) || !validDigest(request.Profile.PackageSnapshotDigest) || !validProfileAuthority(request.Profile) || len(request.Domains) > MaximumDomains || len(request.PublicAddresses) > MaximumPublicAddresses || len(request.BootstrapListeners) > MaximumListenerAuthority || len(request.OwnedListeners) > MaximumListenerAuthority || len(request.ManagedPaths) > MaximumManagedPaths || len(request.Disks) == 0 || len(request.Disks) > MaximumDisks || !canonicalStringSet(request.Domains, canonicalDomain) || !canonicalStringSet(request.PublicAddresses, canonicalIP) {
		return fmt.Errorf("expansion preflight request identity or profile is invalid")
	}
	switch request.Scope {
	case ExpansionBootstrap:
		if request.TemporaryPort != 0 || len(request.Domains) != 0 || len(request.PublicAddresses) != 0 || len(request.BootstrapListeners) != 1 || request.BootstrapListeners[0].Protocol != "tcp" || request.BootstrapListeners[0].Purpose != "management" {
			return fmt.Errorf("bootstrap preflight scope is invalid")
		}
		address, err := netip.ParseAddr(request.BootstrapListeners[0].Address)
		if err != nil || !address.Is4() || !address.IsLoopback() || address.IsUnspecified() || request.BootstrapListeners[0].Port < 49152 {
			return fmt.Errorf("bootstrap Management authority is not an exact 127/8 high port")
		}
	case ExpansionDomainHTTPS:
		if request.TemporaryPort != 0 || len(request.Domains) == 0 || len(request.BootstrapListeners) != 0 {
			return fmt.Errorf("domain HTTPS preflight scope is invalid")
		}
	case ExpansionTemporaryHTTP:
		if request.TemporaryPort < 1024 || request.TemporaryPort == 80 || request.TemporaryPort == 443 || len(request.Domains) != 0 || len(request.PublicAddresses) != 1 || len(request.BootstrapListeners) != 0 {
			return fmt.Errorf("temporary HTTP preflight scope is invalid")
		}
		address, _ := netip.ParseAddr(request.PublicAddresses[0])
		if !address.Is4() || !isPublicAddress(address) {
			return fmt.Errorf("temporary HTTP public IPv4 is not publicly routable")
		}
	case ExpansionHeadscale:
		if request.TemporaryPort != 0 || len(request.Domains) != 1 || len(request.BootstrapListeners) != 0 {
			return fmt.Errorf("Headscale preflight scope is invalid")
		}
	}
	if !validListenerRequirements(request.BootstrapListeners) || !validOwnedListeners(request.OwnedListeners) || !validManagedPaths(request.ManagedPaths) || !validDisks(request.Disks) {
		return fmt.Errorf("expansion preflight path, disk, or listener authority is invalid")
	}
	return nil
}

func validateContractionRequest(request ContractionRequest) error {
	if !validContractionKind(request.Kind) || !validTarget(request.Target) || request.Generation == 0 || len(request.OwnedIngress) > MaximumOwnedIngress || !validDigest(request.OwnershipInventoryDigest) || !validDigest(request.ClosureAuthorityDigest) || !validOwnedIngress(request.OwnedIngress) {
		return fmt.Errorf("contraction preflight authority is invalid")
	}
	return nil
}

func validProfileAuthority(profile ExpectedProfile) bool {
	if profile.ID == "" || profile.ID != strings.ToLower(profile.ID) || profile.VersionID == "" || strings.ContainsAny(profile.ID+profile.VersionID, "\x00\r\n") || !validDigest(profile.Authority.Digest) {
		return false
	}
	if profile.Authority.Kind == QualificationCandidate {
		return !profile.Authority.LiveQualified && validDigest(profile.Authority.CandidateDigest) && validDigest(profile.Authority.ManifestDigest) && refPattern.MatchString(profile.Authority.HostFingerprint) && refPattern.MatchString(profile.Authority.CaseID)
	}
	return profile.Authority.Kind == FinalSupportedProfile && profile.Authority.LiveQualified && profile.Authority.CandidateDigest == "" && profile.Authority.ManifestDigest == "" && profile.Authority.HostFingerprint == "" && profile.Authority.CaseID == ""
}

func requiredListeners(request ExpansionRequest) []ListenerRequirement {
	requirements := append([]ListenerRequirement(nil), request.BootstrapListeners...)
	switch request.Scope {
	case ExpansionDomainHTTPS:
		requirements = append(requirements, ListenerRequirement{Protocol: "tcp", Address: "0.0.0.0", Port: 80, Purpose: "app_http"}, ListenerRequirement{Protocol: "tcp", Address: "0.0.0.0", Port: 443, Purpose: "app_https"})
	case ExpansionTemporaryHTTP:
		requirements = append(requirements, ListenerRequirement{Protocol: "tcp", Address: "0.0.0.0", Port: request.TemporaryPort, Purpose: "temporary_http"})
	case ExpansionHeadscale:
		requirements = append(requirements, ListenerRequirement{Protocol: "tcp", Address: "0.0.0.0", Port: 80, Purpose: "headscale_http"}, ListenerRequirement{Protocol: "tcp", Address: "0.0.0.0", Port: 443, Purpose: "headscale_https"}, ListenerRequirement{Protocol: "udp", Address: "0.0.0.0", Port: 3478, Purpose: "headscale_stun"})
	}
	slices.SortFunc(requirements, compareListenerRequirement)
	return slices.CompactFunc(requirements, func(left, right ListenerRequirement) bool { return compareListenerRequirement(left, right) == 0 })
}

func validateListenerObservations(requirements []ListenerRequirement, owned []OwnedListenerAuthority, observed []ListenerObservation, complete bool) (bool, string) {
	if !complete || !validListenerObservations(observed) {
		return false, "listener_inventory_incomplete"
	}
	ownedBySocket := map[uint64]OwnedListenerAuthority{}
	for _, authority := range owned {
		if authority.IdentityDigest != OwnedListenerDigest(authority.Protocol, authority.Address, authority.Port, authority.SocketInode) {
			return false, "owned_listener_digest_mismatch"
		}
		ownedBySocket[authority.SocketInode] = authority
	}
	conflicts := []string{}
	for _, requirement := range requirements {
		for _, listener := range observed {
			if listener.Protocol != requirement.Protocol || listener.Port != requirement.Port || !socketAddressesOverlap(listener.Address, requirement.Address) {
				continue
			}
			authority, authorized := ownedBySocket[listener.SocketInode]
			if !authorized || authority.Protocol != listener.Protocol || authority.Address != listener.Address || authority.Port != listener.Port {
				conflicts = append(conflicts, listenerIdentity(listener.Protocol, listener.Address, listener.Port, listener.SocketInode))
			}
		}
	}
	if len(conflicts) != 0 {
		return false, strings.Join(conflicts, ",")
	}
	identities := make([]string, len(requirements))
	for index, requirement := range requirements {
		identities[index] = listenerIdentity(requirement.Protocol, requirement.Address, requirement.Port, 0)
	}
	return true, strings.Join(identities, ",")
}

func validatePathObservations(required []ManagedPathRequirement, observed []PathObservation) (bool, string) {
	if len(required) == 0 && len(observed) == 0 {
		return true, "not_applicable"
	}
	if len(required) != len(observed) {
		return false, fmt.Sprintf("observed=%d/required=%d", len(observed), len(required))
	}
	identities := make([]string, 0, len(required))
	for index, requirement := range required {
		value := observed[index]
		if value.Path != requirement.Path || value.Failure != "" || !value.ParentsSafe {
			return false, value.Path + "/" + value.Failure
		}
		if !value.Exists {
			if !requirement.AllowAbsent {
				return false, value.Path + "/missing"
			}
			identities = append(identities, value.Path+"/absent")
			continue
		}
		if value.Kind != requirement.Kind || value.UID != requirement.OwnerUID || value.GID != requirement.OwnerGID || value.Mode&requirement.RequiredMode != requirement.RequiredMode || value.Mode&^requirement.MaximumMode != 0 || value.Device == 0 || value.Inode == 0 {
			return false, value.Path + "/unsafe"
		}
		identities = append(identities, fmt.Sprintf("%s/%d/%d/%o/%d/%d", value.Path, value.UID, value.GID, value.Mode, value.Device, value.Inode))
	}
	return true, strings.Join(identities, ";")
}

func validateDiskObservations(required []DiskRequirement, observed []DiskObservation) (bool, string) {
	if len(required) == 0 && len(observed) == 0 {
		return true, "not_applicable"
	}
	if len(required) != len(observed) {
		return false, fmt.Sprintf("observed=%d/required=%d", len(observed), len(required))
	}
	identities := make([]string, 0, len(required))
	for index, requirement := range required {
		value := observed[index]
		if value.Path != requirement.Path || value.Failure != "" || value.Device == 0 || value.ReadOnly || value.AvailableBytes < requirement.MinimumAvailableBytes {
			return false, value.Path + "/" + value.Failure
		}
		identities = append(identities, fmt.Sprintf("%s/%d/%d", value.Path, value.Device, value.AvailableBytes))
	}
	return true, strings.Join(identities, ";")
}

func publicResponsibilities(request ExpansionRequest) []Finding {
	if request.Scope == ExpansionBootstrap {
		return nil
	}
	ports := []string{}
	for _, listener := range requiredListeners(request) {
		if listener.Address == "0.0.0.0" || listener.Address == "::" {
			ports = append(ports, fmt.Sprintf("%d/%s", listener.Port, listener.Protocol))
		}
	}
	slices.Sort(ports)
	result := []Finding{{Code: "responsibility/cloud_firewall", Disposition: FindingResponsibility, Summary: "administrator must verify cloud and upstream firewall ingress", Identity: strings.Join(ports, ",")}}
	if len(request.Domains) != 0 {
		result = append(result, Finding{Code: "responsibility/public_dns", Disposition: FindingResponsibility, Summary: "administrator must verify authoritative public DNS and external reachability", Identity: strings.Join(request.Domains, ",")})
	}
	if len(request.PublicAddresses) != 0 {
		result = append(result, Finding{Code: "responsibility/public_address", Disposition: FindingResponsibility, Summary: "administrator must verify NAT or public-address mapping", Identity: strings.Join(request.PublicAddresses, ",")})
	} else if request.Scope == ExpansionDomainHTTPS || request.Scope == ExpansionHeadscale {
		result = append(result, Finding{Code: "responsibility/public_address", Disposition: FindingResponsibility, Summary: "administrator must verify NAT or public-address mapping", Identity: "administrator_confirmed_external_mapping_required"})
	}
	return result
}

func validListenerRequirements(values []ListenerRequirement) bool {
	for index, value := range values {
		if value.Protocol != "tcp" && value.Protocol != "udp" || !canonicalIP(value.Address) || value.Port == 0 || !refPattern.MatchString(value.Purpose) || index > 0 && compareListenerRequirement(values[index-1], value) >= 0 {
			return false
		}
	}
	return true
}
func validOwnedListeners(values []OwnedListenerAuthority) bool {
	for index, value := range values {
		if value.Protocol != "tcp" && value.Protocol != "udp" || !canonicalIP(value.Address) || value.Port == 0 || value.SocketInode == 0 || !validDigest(value.IdentityDigest) || index > 0 && compareOwnedListener(values[index-1], value) >= 0 {
			return false
		}
	}
	return true
}
func validListenerObservations(values []ListenerObservation) bool {
	for index, value := range values {
		if value.Protocol != "tcp" && value.Protocol != "udp" || !canonicalIP(value.Address) || value.Port == 0 || value.SocketInode == 0 || index > 0 && compareListenerObservation(values[index-1], value) >= 0 {
			return false
		}
	}
	return true
}
func validManagedPaths(values []ManagedPathRequirement) bool {
	for index, value := range values {
		if !cleanAbsolute(value.Path) || value.Kind != ManagedPathDirectory && value.Kind != ManagedPathRegular || value.RequiredMode == 0 || value.MaximumMode > 0o7777 || value.RequiredMode&^value.MaximumMode != 0 || index > 0 && values[index-1].Path >= value.Path {
			return false
		}
	}
	return true
}
func validDisks(values []DiskRequirement) bool {
	for index, value := range values {
		if !cleanAbsolute(value.Path) || value.MinimumAvailableBytes == 0 || index > 0 && values[index-1].Path >= value.Path {
			return false
		}
	}
	return true
}
func validOwnedIngress(values []OwnedIngressAuthority) bool {
	for index, value := range values {
		if !validTarget(value.ResourceID) || !validDigest(value.RuntimeIdentity) || !validDigest(value.OwnershipDigest) || index > 0 && values[index-1].ResourceID >= value.ResourceID {
			return false
		}
	}
	return true
}
func validDiagnostic(value Diagnostic) bool {
	return refPattern.MatchString(value.Code) && validSummary(value.Summary) && validIdentity(value.Identity)
}

func compareListenerRequirement(left, right ListenerRequirement) int {
	return strings.Compare(listenerIdentity(left.Protocol, left.Address, left.Port, 0), listenerIdentity(right.Protocol, right.Address, right.Port, 0))
}
func compareOwnedListener(left, right OwnedListenerAuthority) int {
	return strings.Compare(listenerIdentity(left.Protocol, left.Address, left.Port, left.SocketInode), listenerIdentity(right.Protocol, right.Address, right.Port, right.SocketInode))
}
func compareListenerObservation(left, right ListenerObservation) int {
	return strings.Compare(listenerIdentity(left.Protocol, left.Address, left.Port, left.SocketInode), listenerIdentity(right.Protocol, right.Address, right.Port, right.SocketInode))
}
func listenerIdentity(protocol, address string, port uint16, inode uint64) string {
	return fmt.Sprintf("%s/%s/%05d/%020d", protocol, address, port, inode)
}

func OwnedListenerDigest(protocol, address string, port uint16, inode uint64) string {
	digest, _ := canonicalDigest(struct {
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
		Port     uint16 `json:"port"`
		Inode    uint64 `json:"inode"`
	}{protocol, address, port, inode})
	return digest
}

func socketAddressesOverlap(left, right string) bool {
	leftAddress, leftErr := netip.ParseAddr(left)
	rightAddress, rightErr := netip.ParseAddr(right)
	if leftErr != nil || rightErr != nil {
		return true
	}
	if leftAddress == rightAddress {
		return true
	}
	if leftAddress.IsUnspecified() || rightAddress.IsUnspecified() {
		return true
	}
	return false
}

func isPublicAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	} {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
