//go:build linux

package packages

import (
	"context"
	"fmt"
	"lanpanel/internal/child"
)

type AuditProvider interface {
	AuditPackages(context.Context, Plan) (Audit, error)
	ObservePackages(context.Context, Plan) (Postcondition, error)
	VerifyPackageMasks(context.Context, []MaskIdentity, bool) error
}

type ChildLauncher interface {
	RunInvocation(context.Context, child.ProfileID, child.Invocation, []byte) (child.Result, error)
}

type HostExecutor struct {
	Auditor  AuditProvider
	Stager   *ArtifactStager
	Files    *TransactionFiles
	Masks    *UnitMasks
	Launcher ChildLauncher
}

func (executor *HostExecutor) Audit(ctx context.Context, plan Plan) (Audit, error) {
	if executor == nil || executor.Auditor == nil {
		return Audit{}, fmt.Errorf("package audit provider is unavailable")
	}
	return executor.Auditor.AuditPackages(ctx, plan)
}

func (executor *HostExecutor) Stage(ctx context.Context, plan Plan) error {
	if executor == nil || executor.Stager == nil {
		return fmt.Errorf("package artifact stager is unavailable")
	}
	return executor.Stager.Stage(ctx, plan)
}

func (executor *HostExecutor) Prepare(ctx context.Context, plan Plan, config, sources []byte) error {
	if executor == nil || executor.Files == nil {
		return fmt.Errorf("package transaction file authority is unavailable")
	}
	return executor.Files.Prepare(ctx, plan, config, sources)
}

func (executor *HostExecutor) Resolve(ctx context.Context, plan Plan) ([]Package, error) {
	if executor == nil || executor.Launcher == nil {
		return nil, fmt.Errorf("package simulation child is unavailable")
	}
	result, err := executor.Launcher.RunInvocation(ctx, child.ProfileAPTSimulate, packageInvocation(plan, true), nil)
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return nil, fmt.Errorf("exact package simulation failed")
	}
	if len(result.PackageChanges) != len(plan.Packages) {
		return nil, fmt.Errorf("package simulation changed the frozen closure size")
	}
	resolved := make([]Package, 0, len(plan.Packages))
	for index, change := range result.PackageChanges {
		want := plan.Packages[index]
		if change.Name != want.Name || change.Version != want.Version {
			return nil, fmt.Errorf("package simulation changed the frozen package identity")
		}
		resolved = append(resolved, want)
	}
	return resolved, nil
}

func (executor *HostExecutor) Mask(ctx context.Context, units []string, persist func(MaskIdentity) error) (MaskResult, error) {
	if executor == nil || executor.Masks == nil || executor.Auditor == nil {
		return MaskResult{}, fmt.Errorf("package mask controller or PID 1 verifier is unavailable")
	}
	result, err := executor.Masks.Mask(ctx, units, persist)
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
	return executor.Launcher.RunInvocation(ctx, profile, invocation, nil)
}

func (executor *HostExecutor) Observe(ctx context.Context, plan Plan) (Postcondition, error) {
	if executor == nil || executor.Auditor == nil {
		return Postcondition{}, fmt.Errorf("package postcondition observer is unavailable")
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
