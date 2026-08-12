//go:build linux

package packages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"lanpanel/internal/child"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/preflight"
)

const (
	FixedPackageRoot        = "/var/lib/lanpanel/packages"
	FixedPackageFileStaging = "/var/lib/lanpanel/packages/.filetxn"
	FixedPackageJournalRoot = "/var/lib/lanpanel/packages/journals"
	FixedPackagePlanRoot    = "/var/lib/lanpanel/packages/plans"
)

type Service struct {
	files    *filetxn.Store
	journal  *FileJournalStore
	auditor  *LinuxAuditor
	engine   Engine
	owner    filetxn.Owner
	planRoot string
	mu       sync.Mutex
}

func OpenFixedService() (*Service, error) {
	owner := filetxn.Owner{UID: 0, GID: 0}
	files, err := filetxn.Open(filetxn.Config{
		RootPath: FixedPackageRoot, Root: filetxn.Metadata{Owner: owner, Mode: 0o700},
		StagingPath: FixedPackageFileStaging, Staging: filetxn.Metadata{Owner: owner, Mode: 0o700},
		StagingParents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{owner}, AllowedMode: 0o700},
	}, filetxn.Options{})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Service, error) {
		_ = files.Close()
		return nil, err
	}
	journals, err := NewFileJournalStore(files, FixedPackageJournalRoot, owner)
	if err != nil {
		return fail(err)
	}
	launcher, err := child.NewLauncher(child.FixedLanPanelExecutable, child.Identities{})
	if err != nil {
		return fail(err)
	}
	auditor, err := NewLinuxAuditor(launcher)
	if err != nil {
		return fail(err)
	}
	transactionFiles, err := NewTransactionFiles()
	if err != nil {
		return fail(err)
	}
	masks, err := NewUnitMasks(FixedSystemdMaskDirectory)
	if err != nil {
		return fail(err)
	}
	stager := &ArtifactStager{Files: transactionFiles, Launcher: launcher}
	executor := &HostExecutor{Auditor: auditor, Stager: stager, Files: transactionFiles, Masks: masks, Launcher: launcher}
	service := &Service{files: files, journal: journals, auditor: auditor, owner: owner, planRoot: FixedPackagePlanRoot}
	service.engine = Engine{Journals: journals, Executor: executor, Monitor: NewLinuxMonitor(), MonitorRequired: false, Now: func() time.Time { return time.Now().UTC() }}
	pending, err := journals.Pending(context.Background())
	if err != nil {
		return fail(fmt.Errorf("audit package recovery journals: %w", err))
	}
	if len(pending) != 0 {
		return fail(fmt.Errorf("unresolved package transaction journal blocks helper startup"))
	}
	return service, nil
}

func (service *Service) Close() error {
	if service == nil || service.files == nil {
		return nil
	}
	return service.files.Close()
}

func (service *Service) ValidateRequest(ctx context.Context, request helperproto.Request) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	_, err := service.loadPlan(ctx, request)
	return err
}

func (service *Service) Execute(ctx context.Context, request helperproto.Request) (string, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	plan, err := service.loadPlan(ctx, request)
	if err != nil {
		return "", err
	}
	preflightResult, err := service.loadPreflight(ctx, request, plan)
	if err != nil {
		return "", err
	}
	journal, err := service.engine.Execute(ctx, plan, preflightResult)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(journal)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (service *Service) loadPreflight(ctx context.Context, request helperproto.Request, plan Plan) (preflight.Result, error) {
	if service == nil || service.files == nil {
		return preflight.Result{}, fmt.Errorf("package preflight authority is unavailable")
	}
	if service.planRoot == "" {
		return preflight.Result{}, fmt.Errorf("package preflight plan root is missing")
	}
	path := filepath.Join(service.planRoot, request.InputDigest[len("sha256:"):]+".preflight.json")
	metadata := filetxn.Metadata{Owner: service.owner, Mode: 0o600}
	data, err := service.files.Read(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{service.owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: maximumJournalBytes})
	if err != nil {
		return preflight.Result{}, fmt.Errorf("read exact package preflight: %w", err)
	}
	var result preflight.Result
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return preflight.Result{}, fmt.Errorf("decode package preflight")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return preflight.Result{}, fmt.Errorf("package preflight has trailing data")
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(canonical, data) || preflight.RequireExpansionResult(result, []preflight.ExpansionScope{preflight.ExpansionBootstrap, preflight.ExpansionHeadscale}, "installation", plan.IntentGeneration, time.Now().UTC()) != nil {
		return preflight.Result{}, fmt.Errorf("package preflight is noncanonical, stale, or intent-mismatched")
	}
	resultDigest, err := result.Digest()
	if err != nil || resultDigest != plan.PreflightDigest || result.RequestDigest != plan.PreflightRequestDigest {
		return preflight.Result{}, fmt.Errorf("package Plan does not bind exact preflight result and request")
	}
	return result, nil
}

func (service *Service) loadPlan(ctx context.Context, request helperproto.Request) (Plan, error) {
	if service == nil || service.files == nil || request.Operation != helperproto.OperationPackageTransaction || request.Target != "installation" {
		return Plan{}, fmt.Errorf("package helper request authority is invalid")
	}
	if err := helperproto.ValidateRequest(request, time.Now().UTC()); err != nil {
		return Plan{}, err
	}
	if pending, err := service.journal.Pending(ctx); err != nil {
		return Plan{}, fmt.Errorf("audit pending package transactions: %w", err)
	} else if len(pending) != 0 {
		return Plan{}, fmt.Errorf("unresolved package transaction blocks new admission")
	}
	digest := request.InputDigest
	if len(digest) != len("sha256:")+64 {
		return Plan{}, fmt.Errorf("package Plan digest is invalid")
	}
	if service.planRoot == "" {
		return Plan{}, fmt.Errorf("package Plan root is missing")
	}
	path := filepath.Join(service.planRoot, digest[len("sha256:"):]+".json")
	metadata := filetxn.Metadata{Owner: service.owner, Mode: 0o600}
	data, err := service.files.Read(ctx, filetxn.Request{Path: path, Parents: filetxn.DirectoryPolicy{AllowedOwners: []filetxn.Owner{service.owner}, AllowedMode: 0o700}, Existing: &metadata, New: metadata, MaxBytes: maximumJournalBytes})
	if err != nil {
		return Plan{}, fmt.Errorf("read exact package Plan: %w", err)
	}
	actual := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(actual[:]) != digest {
		return Plan{}, fmt.Errorf("package Plan digest differs from helper request")
	}
	var plan Plan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("decode package Plan")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Plan{}, fmt.Errorf("package Plan has trailing data")
	}
	canonical, err := json.Marshal(plan)
	if err != nil || !bytes.Equal(canonical, data) || ValidatePlan(plan) != nil || plan.IntentGeneration != request.IntentGeneration || !plan.Deadline.Equal(request.Deadline) || plan.Deadline.Before(time.Now().UTC()) {
		return Plan{}, fmt.Errorf("package Plan is noncanonical, expired, or not bound to helper intent")
	}
	if err := service.verifyCurrentAuthority(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func (service *Service) verifyCurrentAuthority(plan Plan) error {
	if service.auditor == nil {
		return fmt.Errorf("package release authority verifier is unavailable")
	}
	binary, _, err := service.auditor.readFileAndStat(child.FixedLanPanelExecutable, 256<<20)
	if err != nil {
		return err
	}
	binaryDigest := sha256.Sum256(binary)
	if hex.EncodeToString(binaryDigest[:]) != plan.Authority.BinaryDigest {
		return fmt.Errorf("package Plan binary authority differs from the running generation")
	}
	for path, expected := range map[string]string{
		"/var/lib/lanpanel/installation/release-envelope.digest": plan.Authority.EnvelopeDigest,
		"/var/lib/lanpanel/installation/os-profile.digest":       plan.OSProfileDigest,
		"/var/lib/lanpanel/installation/host-fingerprint":        plan.Authority.HostFingerprint,
	} {
		value, stat, err := service.auditor.readFileAndStat(path, 4096)
		if err != nil || stat.Mode&0o777 != 0o600 || string(value) != expected {
			return fmt.Errorf("package Plan release, host, or OS authority differs from installation")
		}
	}
	if plan.Authority.Kind == QualificationCandidate {
		path := filepath.Join("/var/lib/lanpanel/qualification/package-authorities", plan.TransactionID+".json")
		binding, stat, err := service.auditor.readFileAndStat(path, maximumJournalBytes)
		expected, encodeErr := json.Marshal(plan.Authority)
		if err != nil || encodeErr != nil || stat.Mode&0o777 != 0o600 || !bytes.Equal(binding, expected) {
			return fmt.Errorf("package qualification manifest authority is missing or mismatched")
		}
	}
	return nil
}
