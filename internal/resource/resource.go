package resource

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"lanpanel/internal/reservations"
	"path/filepath"
	"slices"
	"strings"
)

const (
	maximumArguments     = 64
	maximumArgumentBytes = 4096
)

type LocalSpec struct {
	Name                string
	EndpointKind        domain.LocalEndpointKind
	TCPAddress          string
	TCPPort             uint16
	ReadinessPath       string
	WebSocket           domain.WebSocketReadiness
	AllowedHTTPStatuses []uint16
	Service             domain.ManagedService
	Publication         domain.AppPublication
	CredentialIDs       []string
}

func NewLocal(spec LocalSpec, random io.Reader) (domain.AppResource, error) {
	if random == nil {
		random = rand.Reader
	}
	resourceID, err := newID(random, "res_")
	if err != nil {
		return domain.AppResource{}, fmt.Errorf("generate resource identity: %w", err)
	}
	processID, err := newID(random, "proc_")
	if err != nil {
		return domain.AppResource{}, fmt.Errorf("generate process identity: %w", err)
	}
	paths, err := DerivePaths(resourceID)
	if err != nil {
		return domain.AppResource{}, err
	}
	statuses := append([]uint16(nil), spec.AllowedHTTPStatuses...)
	if len(statuses) == 0 {
		statuses = []uint16{200, 204}
	}
	target := domain.AppTarget{Kind: domain.AppTargetLocalHTTP, ReadinessPath: spec.ReadinessPath, WebSocket: spec.WebSocket, AllowedHTTPStatuses: statuses, LocalHTTP: &domain.LocalHTTPTarget{EndpointKind: spec.EndpointKind, TCPAddress: spec.TCPAddress, TCPPort: spec.TCPPort}}
	process := &domain.ManagedProcess{ID: processID, Requested: domain.ProcessRequestedStopped, Service: spec.Service}
	resource := domain.AppResource{ID: resourceID, Name: spec.Name, Lifecycle: domain.LifecycleActive, Target: target, Publication: spec.Publication, PublicationRecord: domain.PublicationRecord{State: domain.PublicationUnpublished, UnpublishedGeneration: 1}, ManagedProcess: process, CredentialIDs: append([]string(nil), spec.CredentialIDs...), ManagedPaths: paths.ManagedPaths()}
	digest, err := ConfigDigest(resource)
	if err != nil {
		return domain.AppResource{}, err
	}
	resource.CurrentConfigDigest = digest
	installation := domain.Installation{SchemaVersion: domain.InstallationSchemaVersion, InstallationID: "ins_00000000000000000000000000000001", Management: domain.ManagementAuthority{Address: "127.1.1.1", Port: 49152}, Resources: []domain.AppResource{resource}}
	if err := domain.ValidateInstallation(installation); err != nil {
		return domain.AppResource{}, err
	}
	return resource, nil
}

func ConfigDigest(resource domain.AppResource) (string, error) {
	candidate := resource
	candidate.CurrentConfigDigest = ""
	candidate.PublicationRecord = domain.PublicationRecord{}
	if candidate.ManagedProcess != nil {
		process := *candidate.ManagedProcess
		process.Requested = ""
		process.RuntimeObservation = nil
		process.Applied = nil
		process.LastOperation = ""
		process.LastOperationResult = ""
		process.LastJobID = ""
		candidate.ManagedProcess = &process
	}
	data, err := json.Marshal(candidate)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateCreate(current domain.Installation, candidate domain.AppResource) error {
	if candidate.Lifecycle != domain.LifecycleActive || candidate.PublicationRecord.State != domain.PublicationUnpublished || candidate.PublicationRecord.UnpublishedGeneration != 1 || candidate.PublicationRecord.LastAppliedDigest != nil || candidate.PublicationRecord.LastAppliedBundle != nil || candidate.PublicationRecord.ActivationIntent != nil || candidate.PublicationRecord.ContractionIntent != nil || candidate.PublicationRecord.RuntimeObservation != nil || candidate.ManagedProcess == nil || candidate.ManagedProcess.Requested != domain.ProcessRequestedStopped || candidate.ManagedProcess.RuntimeObservation != nil || candidate.ManagedProcess.Applied != nil || candidate.ManagedProcess.LastJobID != "" {
		return fmt.Errorf("fresh resource must be active, sticky-unpublished, unapplied, and stopped")
	}
	for _, existing := range current.Resources {
		if existing.ID == candidate.ID || strings.EqualFold(existing.Name, candidate.Name) {
			return fmt.Errorf("resource identity or normalized name already exists")
		}
	}
	digest, err := ConfigDigest(candidate)
	if err != nil || digest != candidate.CurrentConfigDigest {
		return fmt.Errorf("resource config digest is not canonical")
	}
	next := current
	next.Resources = append(append([]domain.AppResource(nil), current.Resources...), candidate)
	if err := domain.ValidateInstallation(next); err != nil {
		return err
	}
	_, err = reservations.BuildClaims(next)
	return err
}

func PrepareUpdate(current domain.Installation, candidate domain.AppResource) (domain.AppResource, error) {
	var prior *domain.AppResource
	for index := range current.Resources {
		if current.Resources[index].ID == candidate.ID {
			copy := current.Resources[index]
			prior = &copy
			break
		}
	}
	if prior == nil || prior.Lifecycle != domain.LifecycleActive || prior.ManagedProcess == nil || candidate.ManagedProcess == nil || candidate.ManagedProcess.ID != prior.ManagedProcess.ID || candidate.Target.Kind != domain.AppTargetLocalHTTP {
		return domain.AppResource{}, fmt.Errorf("resource update immutable identity is absent or changed")
	}
	paths, err := DerivePaths(candidate.ID)
	if err != nil {
		return domain.AppResource{}, err
	}
	candidate.ManagedPaths = paths.ManagedPaths()
	candidate.Lifecycle = prior.Lifecycle
	candidate.PublicationRecord = prior.PublicationRecord
	candidate.ManagedProcess.Requested = prior.ManagedProcess.Requested
	candidate.ManagedProcess.ReferenceBinding = nil
	candidate.ManagedProcess.Applied = prior.ManagedProcess.Applied
	candidate.ManagedProcess.RuntimeObservation = prior.ManagedProcess.RuntimeObservation
	candidate.ManagedProcess.LastOperation = prior.ManagedProcess.LastOperation
	candidate.ManagedProcess.LastOperationResult = prior.ManagedProcess.LastOperationResult
	candidate.ManagedProcess.LastJobID = prior.ManagedProcess.LastJobID
	candidate.CurrentConfigDigest = ""
	digest, err := ConfigDigest(candidate)
	if err != nil {
		return domain.AppResource{}, err
	}
	candidate.CurrentConfigDigest = digest
	for _, existing := range current.Resources {
		if existing.ID != candidate.ID && strings.EqualFold(existing.Name, candidate.Name) {
			return domain.AppResource{}, fmt.Errorf("resource normalized name already exists")
		}
	}
	next := current
	next.Resources = append([]domain.AppResource(nil), current.Resources...)
	for index := range next.Resources {
		if next.Resources[index].ID == candidate.ID {
			next.Resources[index] = candidate
		}
	}
	if err := domain.ValidateInstallation(next); err != nil {
		return domain.AppResource{}, err
	}
	if _, err := reservations.BuildClaims(next); err != nil {
		return domain.AppResource{}, err
	}
	return candidate, nil
}

func newID(reader io.Reader, prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(reader, value); err != nil {
		clear(value)
		return "", err
	}
	result := prefix + hex.EncodeToString(value)
	clear(value)
	return result, nil
}

type Paths struct {
	ResourceRoot      string
	FrontendSocket    string
	BackendSocket     string
	BackendSocketUnit string
	ServiceUnit       string
	SocketUnit        string
	RelayUnit         string
	PolicyUnit        string
	SysusersFile      string
}

func DerivePaths(resourceID string) (Paths, error) {
	if !validResourceID(resourceID) {
		return Paths{}, fmt.Errorf("resource identity is invalid")
	}
	short := strings.TrimPrefix(resourceID, "res_")[:20]
	root := filepath.Join("/var/lib/lanpanel/resources", resourceID)
	paths := Paths{ResourceRoot: root, FrontendSocket: filepath.Join("/run/lanpanel/apps", short+".sock"), BackendSocket: filepath.Join(root, "backend", "http.sock"), BackendSocketUnit: "lanpanel-backend-" + short + ".socket", ServiceUnit: "lanpanel-app-" + short + ".service", SocketUnit: "lanpanel-app-" + short + ".socket", RelayUnit: "lanpanel-relay-" + short + ".service", PolicyUnit: "lanpanel-app-" + short + ".slice", SysusersFile: filepath.Join("/etc/lanpanel/sysusers", resourceID+".conf")}
	if len(paths.FrontendSocket) >= 108 || len(paths.BackendSocket) >= 108 {
		return Paths{}, fmt.Errorf("resource Unix socket path exceeds sockaddr_un")
	}
	return paths, nil
}

func (paths Paths) ManagedPaths() []string {
	values := []string{paths.ResourceRoot, paths.FrontendSocket, filepath.Join("/etc/systemd/system", paths.ServiceUnit), filepath.Join("/etc/systemd/system", paths.SocketUnit), filepath.Join("/etc/systemd/system", paths.PolicyUnit), filepath.Join("/etc/systemd/system", paths.BackendSocketUnit), paths.SysusersFile}
	if paths.RelayUnit != "" {
		values = append(values, filepath.Join("/etc/systemd/system", paths.RelayUnit))
	}
	slices.Sort(values)
	return slices.Compact(values)
}

func validResourceID(value string) bool {
	if len(value) != len("res_")+32 || !strings.HasPrefix(value, "res_") {
		return false
	}
	_, err := hex.DecodeString(value[4:])
	return err == nil
}

func ValidateArguments(arguments []string, knownSecretDigests map[string]struct{}) error {
	if len(arguments) > maximumArguments {
		return fmt.Errorf("service argument count exceeds fixed bound")
	}
	bytes := 0
	for _, argument := range arguments {
		bytes += len(argument)
		if argument == "" || len(argument) > 1024 || hasControl(argument) || strings.Contains(argument, "${") || strings.Contains(argument, "$(") || strings.Contains(argument, "`") || strings.Contains(argument, "%") {
			return fmt.Errorf("service argument is empty, unbounded, or contains expansion syntax")
		}
		digest := sha256.Sum256([]byte(argument))
		if _, secret := knownSecretDigests["sha256:"+hex.EncodeToString(digest[:])]; secret {
			return fmt.Errorf("service argument matches protected secret inventory")
		}
	}
	if bytes > maximumArgumentBytes {
		return fmt.Errorf("service arguments exceed fixed byte bound")
	}
	return nil
}
func hasControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
