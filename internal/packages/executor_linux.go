//go:build linux

package packages

import (
	"context"
	"fmt"
	"io"
	"lanpanel/internal/child"
	"strings"
	"sync"
	"time"
)

type AuditProvider interface {
	LockRepositoryMetadata(context.Context, time.Duration) (func(), error)
	AuditPackages(context.Context, Plan) (Audit, error)
	ObservePackages(context.Context, Plan) (Postcondition, error)
	VerifyPackageMasks(context.Context, []MaskIdentity, bool) error
}

type ChildLauncher interface {
	RunInvocation(context.Context, child.ProfileID, child.Invocation, []byte) (child.Result, error)
}

type ProgressChildLauncher interface {
	RunInvocationWithOutput(context.Context, child.ProfileID, child.Invocation, []byte, io.Writer) (child.Result, error)
}

func runChildInvocation(launcher ChildLauncher, ctx context.Context, profile child.ProfileID, invocation child.Invocation, input []byte, progress io.Writer) (child.Result, error) {
	if progressLauncher, ok := launcher.(ProgressChildLauncher); ok {
		return progressLauncher.RunInvocationWithOutput(ctx, profile, invocation, input, progress)
	}
	return launcher.RunInvocation(ctx, profile, invocation, input)
}

type structuredProgressWriter struct {
	writer   io.Writer
	report   ProgressReporter
	profile  child.ProfileID
	current  int
	total    int
	packages map[string]struct{}
	lines    []byte
	mu       sync.Mutex
}

func (writer *structuredProgressWriter) Write(value []byte) (int, error) {
	if writer == nil {
		return len(value), nil
	}
	_, _ = writer.writer.Write(value)
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.lines = append(writer.lines, value...)
	for {
		index := strings.IndexAny(string(writer.lines), "\r\n")
		if index < 0 {
			if len(writer.lines) > 4096 {
				writer.lines = writer.lines[len(writer.lines)-4096:]
			}
			break
		}
		line := strings.TrimSpace(string(writer.lines[:index]))
		writer.lines = writer.lines[index+1:]
		if line != "" && aptProgressLine(line) && writer.report != nil {
			if strings.HasPrefix(line, "Unpacking ") || strings.HasPrefix(line, "Setting up ") {
				name := strings.Fields(strings.TrimPrefix(strings.TrimPrefix(line, "Unpacking "), "Setting up "))
				if len(name) != 0 {
					if writer.packages == nil {
						writer.packages = make(map[string]struct{})
					}
					writer.packages[name[0]] = struct{}{}
					writer.current = len(writer.packages)
				}
			}
			if writer.total > 0 && writer.current > writer.total {
				writer.current = writer.total
			}
			if len(line) > 512 {
				line = line[:512]
			}
			writer.report(ProgressEvent{Stage: aptProgressStage(writer.profile), State: "update", Profile: string(writer.profile), Current: writer.current, Total: writer.total, Message: line})
		}
	}
	return len(value), nil
}

func aptProgressLine(line string) bool {
	for _, prefix := range []string{"Get:", "Fetched ", "Reading package lists", "Building dependency tree", "Reading state information", "Selecting previously", "Preparing to unpack", "Unpacking ", "Setting up ", "Processing triggers", "Progress:"} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func aptProgressStage(profile child.ProfileID) string {
	switch profile {
	case child.ProfileAPTDownload:
		return "apt_download"
	case child.ProfileAPTSimulate:
		return "apt_simulation"
	default:
		return "apt_dpkg_transaction"
	}
}

func wrapProgressWriter(writer io.Writer, report ProgressReporter, profile child.ProfileID, total int) io.Writer {
	if writer == nil || report == nil {
		return writer
	}
	return &structuredProgressWriter{writer: writer, report: report, profile: profile, total: total, packages: make(map[string]struct{})}
}

type HostExecutor struct {
	Auditor  AuditProvider
	Stager   *ArtifactStager
	Files    *TransactionFiles
	Masks    *UnitMasks
	Launcher ChildLauncher
	Progress io.Writer
	Report   ProgressReporter
}

func (executor *HostExecutor) LockRepositories(ctx context.Context, plan Plan) (func(), error) {
	if plan.Mode != DistroRepository {
		return func() {}, nil
	}
	if executor == nil || executor.Auditor == nil {
		return nil, fmt.Errorf("package repository metadata lock is unavailable")
	}
	return executor.Auditor.LockRepositoryMetadata(ctx, plan.LockWait)
}

func (executor *HostExecutor) Audit(ctx context.Context, plan Plan) (Audit, error) {
	if executor == nil || executor.Auditor == nil {
		return Audit{}, fmt.Errorf("package audit provider is unavailable")
	}
	return executor.Auditor.AuditPackages(ctx, plan)
}

func (executor *HostExecutor) Stage(ctx context.Context, plan Plan) error {
	if plan.Mode == DistroRepository && len(plan.Repositories) == 0 {
		return executor.verifyTransactionFiles(ctx, plan)
	}
	if executor == nil || executor.Stager == nil {
		return fmt.Errorf("package artifact stager is unavailable")
	}
	return executor.Stager.Stage(ctx, plan)
}

func (executor *HostExecutor) VerifyStaged(ctx context.Context, plan Plan) error {
	if plan.Mode == DistroRepository && len(plan.Repositories) == 0 {
		return nil
	}
	if executor == nil || executor.Files == nil {
		return fmt.Errorf("package staged artifact verifier is unavailable")
	}
	return executor.Files.validateStagedClosure(ctx, plan)
}

func (executor *HostExecutor) Prepare(ctx context.Context, plan Plan, config, sources []byte) error {
	if executor == nil || executor.Files == nil {
		return fmt.Errorf("package transaction file authority is unavailable")
	}
	return executor.Files.Prepare(ctx, plan, config, sources)
}

func (executor *HostExecutor) verifyTransactionFiles(ctx context.Context, plan Plan) error {
	if executor == nil || executor.Files == nil {
		return fmt.Errorf("package transaction file authority is unavailable")
	}
	config, sources, err := RenderAPTConfiguration(plan)
	if err != nil {
		return err
	}
	return executor.Files.Prepare(ctx, plan, config, sources)
}

func (executor *HostExecutor) Resolve(ctx context.Context, plan Plan) ([]Package, error) {
	if executor == nil || executor.Launcher == nil {
		return nil, fmt.Errorf("package simulation child is unavailable")
	}
	if plan.Mode == DistroRepository && len(plan.Repositories) == 0 {
		if err := executor.verifyTransactionFiles(ctx, plan); err != nil {
			return nil, fmt.Errorf("verify exact package transaction files: %w", err)
		}
	}
	staged := plan.Mode == StagedDebs || plan.Mode == OfflineDebs
	result, err := runChildInvocation(executor.Launcher, ctx, child.ProfileAPTSimulate, packageInvocation(plan, staged), nil, wrapProgressWriter(executor.Progress, executor.Report, child.ProfileAPTSimulate, len(plan.Packages)))
	if err != nil {
		return nil, fmt.Errorf("exact package simulation failed: %w", err)
	}
	if result.ExitCode != 0 || result.OutputCutOff {
		return nil, fmt.Errorf("exact package simulation failed: exit code %d, output cut off %t", result.ExitCode, result.OutputCutOff)
	}
	if len(result.PackageChanges) == 0 {
		if plan.Mode == DistroRepository && !plan.FirstNginxInstall {
			return append([]Package(nil), plan.Packages...), nil
		}
		return nil, fmt.Errorf("package simulation returned an invalid closure")
	}
	if len(result.PackageChanges) > 256 {
		return nil, fmt.Errorf("package simulation returned an invalid closure")
	}
	flexible := false
	for _, pkg := range plan.Packages {
		flexible = flexible || pkg.VersionMinimum != "" || pkg.VersionMaximum != ""
	}
	if !flexible && len(result.PackageChanges) != len(plan.Packages) {
		return nil, fmt.Errorf("package simulation changed the frozen closure size")
	}
	resolved := make([]Package, 0, len(plan.Packages))
	for _, want := range plan.Packages {
		found := false
		for _, change := range result.PackageChanges {
			if change.Name == want.Name {
				if found || !PackageVersionMatches(want, change.Version) {
					return nil, fmt.Errorf("package simulation changed the package version requirement")
				}
				found = true
			}
		}
		if !found && !flexible {
			return nil, fmt.Errorf("package simulation omitted required package %q", want.Name)
		}
		resolved = append(resolved, want)
	}
	return resolved, nil
}

func (executor *HostExecutor) Mask(ctx context.Context, units []string, pendingIntent string, persistIntent func(string) error, persistIdentity func(MaskIdentity) error) (MaskResult, error) {
	if executor == nil || executor.Masks == nil || executor.Auditor == nil {
		return MaskResult{}, fmt.Errorf("package mask controller or PID 1 verifier is unavailable")
	}
	result, err := executor.Masks.Mask(ctx, units, pendingIntent, persistIntent, persistIdentity)
	if err != nil {
		return result, err
	}
	if err := executor.Auditor.VerifyPackageMasks(ctx, result.Masks, true); err != nil {
		return result, fmt.Errorf("PID 1 did not observe exact package masks: %w", err)
	}
	return result, nil
}

func (executor *HostExecutor) VerifyMasks(ctx context.Context, masks []MaskIdentity) error {
	if executor == nil || executor.Masks == nil || executor.Auditor == nil {
		return fmt.Errorf("package mask controller or PID 1 verifier is unavailable")
	}
	if err := executor.Masks.Verify(ctx, masks); err != nil {
		return err
	}
	return executor.Auditor.VerifyPackageMasks(ctx, masks, true)
}

func (executor *HostExecutor) Run(ctx context.Context, profile child.ProfileID, invocation child.Invocation) (child.Result, error) {
	if executor == nil || executor.Launcher == nil {
		return child.Result{}, fmt.Errorf("package child launcher is unavailable")
	}
	if profile != child.ProfileAPTTransaction && profile != child.ProfileAPTOfflineTransaction {
		return child.Result{}, fmt.Errorf("package executor rejected a non-package child profile")
	}
	total := 0
	if invocation.Package != nil {
		total = len(invocation.Package.Packages)
	}
	return runChildInvocation(executor.Launcher, ctx, profile, invocation, nil, wrapProgressWriter(executor.Progress, executor.Report, profile, total))
}

func (executor *HostExecutor) Observe(ctx context.Context, plan Plan) (Postcondition, error) {
	if executor == nil || executor.Auditor == nil || executor.Files == nil {
		return Postcondition{}, fmt.Errorf("package postcondition observer is unavailable")
	}
	if plan.Mode != DistroRepository || len(plan.Repositories) != 0 {
		if err := executor.Files.validateStagedClosure(ctx, plan); err != nil {
			return Postcondition{}, fmt.Errorf("postcondition staged package artifact audit: %w", err)
		}
	}
	return executor.Auditor.ObservePackages(ctx, plan)
}

func (executor *HostExecutor) Unmask(ctx context.Context, masks []MaskIdentity) error {
	if executor == nil || executor.Masks == nil || executor.Auditor == nil {
		return fmt.Errorf("package mask controller or PID 1 verifier is unavailable")
	}
	if err := executor.Masks.Unmask(ctx, masks); err != nil {
		return err
	}
	return executor.Auditor.VerifyPackageMasks(ctx, masks, false)
}
