//go:build linux

package helper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/application"
	"lanpanel/internal/certificates"
	"lanpanel/internal/child"
	managedconnector "lanpanel/internal/connector"
	"lanpanel/internal/contraction"
	"lanpanel/internal/domain"
	"lanpanel/internal/filetxn"
	managedheadscale "lanpanel/internal/headscale"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	managedprocess "lanpanel/internal/process"
	"lanpanel/internal/renewal"
	"lanpanel/internal/resource"
	"lanpanel/internal/secrets"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	FixedIdentityConfigPath    = "/var/lib/lanpanel/installation/helper-identities.json"
	identityConfigSchema       = "lanpanel.helper.identities.v1"
	maximumIdentityConfigBytes = 4096
)

type IdentityConfig struct {
	SchemaVersion string      `json:"schema_version"`
	SocketGroup   uint32      `json:"socket_group"`
	Identities    IdentitySet `json:"identities"`
}

// RunRole starts the fixed root helper role. Component operations remain
// unavailable until their owning package registers a complete typed handler.
func RunRole(args []string) error {
	if len(args) != 0 || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("helper role requires its fixed root service invocation")
	}
	config, err := ReadIdentityConfig()
	if err != nil {
		return err
	}
	fingerprint, err := secrets.CurrentAdminTokenFingerprint()
	if err != nil {
		return fmt.Errorf("read admin token before helper recovery: %w", err)
	}
	adminRecoveryErr := application.ReconcileAdminTokenRotation(context.Background(), fingerprint)
	var otherRecoveryErr error
	recordRecovery := func(err error) { otherRecoveryErr = errors.Join(otherRecoveryErr, err) }
	recordRecovery(cleanupConnectorLoginSecrets())
	recordRecovery(application.ReconcileStaticRootRegistrations(context.Background()))
	childClosure, childErr := child.ObserveExclusiveCurrentCgroup()
	recordRecovery(childErr)
	if childErr == nil {
		recordRecovery(application.ReconcileInterruptedEntityMutations(context.Background(), childClosure))
		recordRecovery(application.ReconcileManagedBasic(context.Background(), childClosure))
		recordRecovery(application.ReconcileCertificateChallenges(context.Background(), childClosure))
		recordRecovery(application.ReconcileJournalLessCertificateIntents(context.Background(), childClosure))
		recordRecovery(application.ReconcileUnstartedCertificateJournals(context.Background(), childClosure))
	}
	recordRecovery(application.ReconcileCompletedCertificateRenewals(context.Background()))
	recordRecovery(application.ReconcileInterruptedDomainPublications(context.Background()))
	recordRecovery(application.ReconcileCertificateExpiries(context.Background(), time.Now().UTC()))
	recordRecovery(application.ReconcileResourceCreates(context.Background()))
	recordRecovery(application.ReconcileResourceUpdates(context.Background()))
	recordRecovery(application.ReconcileResourceDeletes(context.Background()))
	recordRecovery(application.ReconcileJournalLessProcesses(context.Background()))
	if host, hostErr := managedprocess.NewFixedHost(); hostErr == nil {
		recordRecovery(managedprocess.ReconcileJournals(context.Background(), host, application.ReconcileInterruptedProcess))
	} else {
		recordRecovery(hostErr)
	}
	recordRecovery(reconcileStartupContraction(context.Background()))
	var tokenMu sync.Mutex
	contractionPlans := newEmergencyPlanStore()
	applicationHandler := ApplicationPlanHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Action == nil {
			return fmt.Errorf("application caller invalid")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("application request carried secret")
		}
		if request.Action.Operation == "close_all" || request.Action.Operation == "unpublish" {
			service, normalErr := application.OpenFixed()
			if normalErr == nil {
				if _, readErr := service.Normal().Read(); readErr != nil {
					if closeErr := service.Close(); closeErr != nil {
						return ExecutionResult{}, errors.Join(readErr, closeErr)
					}
				} else {
					operation := domain.OperationCloseAll
					target := domain.OperationTarget{Kind: domain.OperationTargetInstallation}
					if request.Action.Operation == "unpublish" {
						operation = domain.OperationUnpublish
						target = domain.OperationTarget{Kind: domain.OperationTargetResource, ID: request.Action.TargetID}
					}
					plan, createErr := service.CreatePlan(ctx, application.Actor{Kind: application.ActorUI, Identity: request.Action.ActorIdentity, Generation: request.Action.ActorGeneration}, application.PlanPayload{Operation: operation, Target: target})
					closeErr := service.Close()
					if createErr != nil || closeErr != nil {
						return ExecutionResult{}, errors.Join(createErr, closeErr)
					}
					return ExecutionResult{ResultDigest: request.InputDigest, Action: &helperproto.ActionResult{PlanID: plan.ID, Confirmation: plan.NonceDigest, Operation: request.Action.Operation, TargetKind: request.Action.TargetKind, TargetID: request.Action.TargetID, ExposureSummary: plan.ExposureSummary, Prerequisites: plan.Prerequisites, ExpiresAt: plan.ExpiresAt}}, nil
				}
			}
			if request.Action.Operation == "unpublish" {
				return ExecutionResult{}, fmt.Errorf("normal unpublish authority is unavailable")
			}
			plan, planErr := contractionPlans.Create(ctx, application.Actor{Kind: application.ActorUI, Identity: request.Action.ActorIdentity, Generation: request.Action.ActorGeneration})
			if planErr != nil {
				return ExecutionResult{}, planErr
			}
			return ExecutionResult{ResultDigest: request.InputDigest, Action: &helperproto.ActionResult{PlanID: plan.ID, Confirmation: plan.ConfirmationDigest, Operation: "close_all", TargetKind: "installation", ExposureSummary: "closes_all_app_origin_ingress", Prerequisites: "emergency_authenticated_destructive_confirmation", ExpiresAt: plan.ExpiresAt}}, nil
		}
		tokenMu.Lock()
		recoveryErr := errors.Join(adminRecoveryErr, otherRecoveryErr)
		tokenMu.Unlock()
		if recoveryErr != nil {
			return ExecutionResult{}, fmt.Errorf("normal application authority is degraded")
		}
		service, err := application.OpenFixed()
		if err != nil {
			return ExecutionResult{}, err
		}
		defer func(ignore func() error) { _ = ignore() }(service.Close)
		operation, err := domain.ParseOperationCode(request.Action.Operation)
		if err != nil {
			return ExecutionResult{}, err
		}
		target := domain.OperationTarget{Kind: domain.OperationTargetKind(request.Action.TargetKind), ID: request.Action.TargetID}
		plan, err := service.CreatePlan(ctx, application.Actor{Kind: application.ActorUI, Identity: request.Action.ActorIdentity, Generation: request.Action.ActorGeneration}, application.PlanPayload{Operation: operation, Target: target})
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: request.InputDigest, Action: &helperproto.ActionResult{PlanID: plan.ID, Confirmation: plan.NonceDigest, Operation: plan.Operation, TargetKind: string(plan.Target.Kind), TargetID: plan.Target.ID, ExposureSummary: plan.ExposureSummary, Prerequisites: plan.Prerequisites, ExpiresAt: plan.ExpiresAt}}, nil
	})
	authRevalidate := func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Target != "installation" {
			return fmt.Errorf("admin token caller is unauthorized")
		}
		return nil
	}
	verifyHandler := AdminTokenVerifyHandler(authRevalidate, func(_ context.Context, _ helperproto.Caller, _ helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret == nil {
			return ExecutionResult{}, fmt.Errorf("admin token source is unavailable")
		}
		var fingerprint string
		err := secret.Use(func(value []byte) error {
			var verifyErr error
			fingerprint, verifyErr = verifyAdminToken(value)
			return verifyErr
		})
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: fingerprint}, nil
	})
	sourceHandler := AdminTokenSourceHandler(authRevalidate, func(_ context.Context, _ helperproto.Caller, _ helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("admin token source request carried secret")
		}
		source, fingerprint, err := readAdminToken()
		clear(source)
		return ExecutionResult{ResultDigest: fingerprint}, err
	})
	rotateHandler := AdminTokenRotateHandler(authRevalidate, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		tokenMu.Lock()
		defer tokenMu.Unlock()
		if errors.Join(adminRecoveryErr, otherRecoveryErr) != nil {
			return ExecutionResult{}, fmt.Errorf("startup recovery is unresolved")
		}
		if secret != nil || request.Action == nil || request.Action.Operation != "admin_token_rotate" || request.Action.TargetKind != "installation" {
			return ExecutionResult{}, fmt.Errorf("admin token rotation input is invalid")
		}
		rotation, err := application.BeginAdminTokenRotation(ctx, application.Actor{Kind: application.ActorUI, Identity: request.Action.ActorIdentity, Generation: request.Action.ActorGeneration}, application.ConfirmationPayload{PlanID: request.Action.PlanID, Confirmation: request.Action.Confirmation})
		if err != nil {
			return ExecutionResult{}, err
		}
		defer func() { _ = rotation.Close() }()
		candidate, err := secrets.GenerateAdminToken(secrets.AdminTokenOptions{})
		if err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, terminalErr := rotation.Fail(cleanupCtx, false, ""); terminalErr != nil {
				return ExecutionResult{}, fmt.Errorf("admin token generation failed and terminalization failed: %v: %w", err, terminalErr)
			}
			return ExecutionResult{}, err
		}
		// Plaintext generation occurs only after BeginAdminTokenRotation durably reserved and consumed the Plan/job/intent.
		fingerprint, err := candidate.Fingerprint()
		if err != nil {
			candidate.Destroy()
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, terminalErr := rotation.Fail(cleanupCtx, false, ""); terminalErr != nil {
				return ExecutionResult{}, fmt.Errorf("admin token fingerprint failed and terminalization failed: %v: %w", err, terminalErr)
			}
			return ExecutionResult{}, err
		}
		if err := rotation.BindFingerprint(ctx, fingerprint); err != nil {
			candidate.Destroy()
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, terminalErr := rotation.Fail(cleanupCtx, false, ""); terminalErr != nil {
				return ExecutionResult{}, fmt.Errorf("admin token binding failed and terminalization failed: %v: %w", err, terminalErr)
			}
			return ExecutionResult{}, err
		}
		commit, err := secrets.CommitAdminToken(candidate, secrets.AdminTokenOptions{ExpectedFingerprint: rotation.PriorFingerprint()})
		if err != nil {
			if commit.Value != nil {
				commit.Value.Destroy()
			}
			return ExecutionResult{}, err
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := rotation.MarkCommitted(cleanupCtx, commit.Fingerprint); err != nil {
			cancel()
			commit.Value.Destroy()
			return ExecutionResult{}, fmt.Errorf("mark admin token committed: %w", err)
		}
		if err := secrets.FinalizeAdminToken(rotation.PriorFingerprint(), commit.Fingerprint); err != nil {
			cancel()
			commit.Value.Destroy()
			return ExecutionResult{}, fmt.Errorf("finalize admin token: %w", err)
		}
		job, err := rotation.Finish(cleanupCtx, commit.Fingerprint)
		cancel()
		if err != nil {
			commit.Value.Destroy()
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, terminalErr := rotation.Fail(cleanupCtx, true, commit.Fingerprint); terminalErr != nil {
				return ExecutionResult{}, fmt.Errorf("admin token success and failure terminalization both failed: %v: %w", err, terminalErr)
			}
			return ExecutionResult{}, fmt.Errorf("admin token committed but success terminalization failed: %w", err)
		}
		var output *helperproto.Secret
		err = commit.Value.Use(func(value []byte) error {
			var createErr error
			output, createErr = helperproto.NewOutputSecret(value)
			return createErr
		})
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: commit.Fingerprint, Secret: output, Action: &helperproto.ActionResult{JobID: job.ID}}, nil
	})
	reconcileHandler := AdminTokenReconcileHandler(authRevalidate, func(ctx context.Context, _ helperproto.Caller, _ helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("admin token reconciliation carried secret")
		}
		tokenMu.Lock()
		defer tokenMu.Unlock()
		fingerprint, err := secrets.CurrentAdminTokenFingerprint()
		if err != nil {
			return ExecutionResult{}, err
		}
		if err := application.ReconcileAdminTokenRotation(ctx, fingerprint); err != nil {
			adminRecoveryErr = err
			return ExecutionResult{}, err
		}
		adminRecoveryErr = nil
		fingerprint, err = secrets.CurrentAdminTokenFingerprint()
		return ExecutionResult{ResultDigest: fingerprint}, err
	})
	contractionHandler := ContractionCloseHandler(func(ctx context.Context, caller helperproto.Caller, request helperproto.Request) error {
		validTarget := request.Action != nil && (request.Target == "installation" && request.Action.Operation == "close_all" || request.Target == "resource/"+request.Action.TargetID && request.Action.Operation == "unpublish")
		if caller != helperproto.CallerUI || !validTarget {
			return fmt.Errorf("close-all caller is unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("close-all request carried secret")
		}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Action.ActorIdentity, Generation: request.Action.ActorGeneration}
		var normalExecution *application.CloseAllExecution
		var normalErr error
		if request.Action.Operation == "unpublish" {
			normalExecution, normalErr = application.BeginUnpublish(ctx, actor, domain.OperationTarget{Kind: domain.OperationTargetResource, ID: request.Action.TargetID}, application.ConfirmationPayload{PlanID: request.Action.PlanID, Confirmation: request.Action.Confirmation})
		} else {
			normalExecution, normalErr = application.BeginCloseAll(ctx, actor, application.ConfirmationPayload{PlanID: request.Action.PlanID, Confirmation: request.Action.Confirmation})
		}
		if normalErr == nil {
			inventoryDigest := normalExecution.Inventory.Digest
			result, runErr := normalExecution.Run(ctx)
			action := &helperproto.ActionResult{ContractionOutcome: string(result.Outcome), AccessClosed: result.AccessClosed, SharedIngressDown: result.SharedIngressDown, AccessMayRemain: result.AccessMayRemain}
			if result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown {
				if runErr != nil {
					return ExecutionResult{}, runErr
				}
				return ExecutionResult{ResultDigest: inventoryDigest, Action: action}, nil
			}
			if runErr != nil {
				return ExecutionResult{}, runErr
			}
			return ExecutionResult{ResultDigest: result.ClosureDigest, Action: action}, nil
		}
		if request.Action.Operation == "unpublish" {
			return ExecutionResult{}, normalErr
		}
		plan, err := contractionPlans.Consume(request.Action.PlanID, request.Action.ActorIdentity, request.Action.ActorGeneration, request.Action.Confirmation, time.Now().UTC())
		if err != nil {
			return ExecutionResult{}, fmt.Errorf("normal and emergency close-all authority rejected")
		}
		service, err := contraction.OpenEmergency(ctx)
		if err != nil {
			return ExecutionResult{}, err
		}
		defer func(ignore func() error) { _ = ignore() }(service.Close)
		result, runErr := service.Run(ctx, plan.GlobalGeneration, plan.InventoryDigest)
		action := &helperproto.ActionResult{ContractionOutcome: string(result.Outcome), AccessClosed: result.AccessClosed, SharedIngressDown: result.SharedIngressDown, AccessMayRemain: result.AccessMayRemain}
		if result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown {
			return ExecutionResult{ResultDigest: plan.InventoryDigest, Action: action}, nil
		}
		if runErr != nil {
			return ExecutionResult{}, runErr
		}
		return ExecutionResult{ResultDigest: result.ClosureDigest, Action: action}, nil
	})
	startupHandler := StartupContractionHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerRecovery || request.Target != "installation" || request.Action != nil {
			return fmt.Errorf("startup contraction caller is unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("startup contraction carried secret")
		}
		headscaleErr := application.ReconcileHeadscaleInitialization(ctx)
		if headscaleErr == nil {
			if normal, normalErr := application.OpenFixed(); normalErr == nil {
				allowed, guardErr := normal.NginxStartAllowed(time.Now().UTC())
				recoveryErr := normal.PendingPublicationRecovery()
				_ = normal.Close()
				if guardErr == nil && recoveryErr == nil && allowed {
					return ExecutionResult{ResultDigest: request.InputDigest}, nil
				}
			}
		}
		service, err := contraction.OpenEmergency(ctx)
		if err != nil {
			return ExecutionResult{}, err
		}
		defer func(ignore func() error) { _ = ignore() }(service.Close)
		snapshot, err := service.Snapshot()
		if err != nil {
			return ExecutionResult{}, err
		}
		if recoverErr := service.RecoverClosed(ctx, snapshot.GlobalGeneration, snapshot.Inventory.Digest); recoverErr == nil {
			return ExecutionResult{ResultDigest: snapshot.Inventory.Digest}, nil
		}
		result, runErr := service.Run(ctx, snapshot.GlobalGeneration, snapshot.Inventory.Digest)
		if result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown {
			return ExecutionResult{}, errors.Join(runErr, fmt.Errorf("startup contraction did not converge: %s", result.Outcome))
		}
		if runErr != nil {
			return ExecutionResult{}, runErr
		}
		return ExecutionResult{ResultDigest: result.ClosureDigest}, nil
	})
	headscaleHandler := HeadscaleInitializeHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Action != nil || request.Target != "installation" {
			return fmt.Errorf("headscale initialization caller is unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil || request.Resource.Operation != string(domain.OperationHeadscaleInitialize) {
			return ExecutionResult{}, fmt.Errorf("headscale initialization payload is invalid")
		}
		var payload application.HeadscaleInitializePayload
		decoder := json.NewDecoder(bytes.NewReader(request.Resource.Resource))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return ExecutionResult{}, fmt.Errorf("headscale initialization config is invalid")
		}
		job, headscaleID, authorityDigest, err := application.InitializeHeadscale(ctx, application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}, payload)
		if err != nil {
			if errors.Is(err, managedheadscale.ErrForeignEvidence) {
				return ExecutionResult{ErrorCode: "foreign_database_evidence", ErrorJobID: job.ID}, err
			}
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: authorityDigest, Action: &helperproto.ActionResult{JobID: job.ID, Operation: string(domain.OperationHeadscaleInitialize), TargetKind: string(domain.OperationTargetInstallation), TargetID: headscaleID}}, nil
	})
	headscaleDeployHandler := HeadscaleDeployHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Target != "headscale" {
			return fmt.Errorf("headscale deploy caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("headscale deploy payload invalid")
		}
		var config application.HeadscaleCertificateConfig
		decoder := json.NewDecoder(bytes.NewReader(request.Resource.Resource))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return ExecutionResult{}, fmt.Errorf("headscale certificate config invalid")
		}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		if request.Resource.Confirmation == "plan" {
			service, err := application.OpenFixed()
			if err != nil {
				return ExecutionResult{}, err
			}
			plan, planErr := service.CreateHeadscaleDeployPlan(ctx, actor, config)
			closeErr := service.Close()
			if planErr != nil || closeErr != nil {
				return ExecutionResult{}, errors.Join(planErr, closeErr)
			}
			return ExecutionResult{ResultDigest: digestString(plan.ID), Action: &helperproto.ActionResult{PlanID: plan.ID, Operation: string(domain.OperationHeadscaleControlDeploy), TargetKind: "headscale", ExposureSummary: plan.ExposureSummary, Prerequisites: plan.Prerequisites, ExpiresAt: plan.ExpiresAt}}, nil
		}
		record, err := application.ExecuteHeadscaleDeploy(ctx, actor, application.HeadscaleDeployPayload{PlanID: request.Resource.PlanID, Confirmation: request.Resource.Confirmation, Certificate: config})
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: digestString(record.ID), Action: &helperproto.ActionResult{JobID: record.ID, JobResult: string(record.Result), Operation: string(domain.OperationHeadscaleControlDeploy), TargetKind: "headscale", TargetID: "headscale"}}, nil
	})
	headscaleReissueHandler := HeadscaleReissueHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Target != "headscale" {
			return fmt.Errorf("headscale reissue caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("headscale reissue payload invalid")
		}
		var config application.HeadscaleCertificateConfig
		decoder := json.NewDecoder(bytes.NewReader(request.Resource.Resource))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&config) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return ExecutionResult{}, fmt.Errorf("headscale reissue config invalid")
		}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		if request.Resource.Confirmation == "plan" {
			service, err := application.OpenFixed()
			if err != nil {
				return ExecutionResult{}, err
			}
			plan, planErr := service.CreateHeadscaleReissuePlan(ctx, actor, config)
			closeErr := service.Close()
			if planErr != nil || closeErr != nil {
				return ExecutionResult{}, errors.Join(planErr, closeErr)
			}
			return ExecutionResult{ResultDigest: digestString(plan.ID), Action: &helperproto.ActionResult{PlanID: plan.ID, Operation: string(domain.OperationHeadscaleReissue), TargetKind: "headscale", ExposureSummary: plan.ExposureSummary, Prerequisites: plan.Prerequisites, ExpiresAt: plan.ExpiresAt}}, nil
		}
		record, err := application.ExecuteHeadscaleCertificateReissue(ctx, actor, application.HeadscaleReissuePayload{PlanID: request.Resource.PlanID, Confirmation: request.Resource.Confirmation, Certificate: config})
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: digestString(record.ID), Action: &helperproto.ActionResult{JobID: record.ID, JobResult: string(record.Result), Operation: string(domain.OperationHeadscaleReissue), TargetKind: "headscale", TargetID: "headscale"}}, nil
	})
	headscaleReadHandler := HeadscaleReadHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Target != "headscale" {
			return fmt.Errorf("headscale read caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("headscale read payload invalid")
		}
		result := &helperproto.HeadscaleResult{Operation: request.Resource.Operation}
		switch request.Resource.Operation {
		case string(domain.OperationHeadscaleUserList):
			value, err := application.ListHeadscaleUsers(ctx, nil)
			if err != nil {
				return ExecutionResult{}, err
			}
			result.Users = helperUsers(value.Users)
		case string(domain.OperationPreauthKeyList):
			value, err := application.ListHeadscalePreauthKeys(ctx, nil)
			if err != nil {
				return ExecutionResult{}, err
			}
			result.Keys = helperKeys(value.Keys)
		case string(domain.OperationDeviceList):
			value, err := application.ListHeadscaleDevices(ctx, nil)
			if err != nil {
				return ExecutionResult{}, err
			}
			result.Devices = helperDevices(value.Devices)
		default:
			return ExecutionResult{}, fmt.Errorf("headscale read operation unavailable")
		}
		return ExecutionResult{ResultDigest: digestString(request.Resource.Operation), Headscale: result}, nil
	})
	headscaleMutationHandler := HeadscaleMutationHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil {
			return fmt.Errorf("headscale mutation caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("headscale mutation payload invalid")
		}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		result := &helperproto.HeadscaleResult{Operation: request.Resource.Operation}
		switch request.Resource.Operation {
		case string(domain.OperationHeadscaleUserCreate):
			var payload application.HeadscaleUserPayload
			if err := decodeHeadscalePayload(request.Resource.Resource, &payload); err != nil {
				return ExecutionResult{}, err
			}
			value, err := application.CreateHeadscaleUser(ctx, actor, payload, nil)
			if err != nil {
				return ExecutionResult{}, err
			}
			user := helperUser(value.User)
			result.JobID, result.User = value.JobID, &user
		case string(domain.OperationPreauthKeyRevoke), string(domain.OperationDeviceExpire):
			var payload application.HeadscaleLifecyclePayload
			if err := decodeHeadscalePayload(request.Resource.Resource, &payload); err != nil {
				return ExecutionResult{}, err
			}
			kind, id, _ := strings.Cut(request.Target, "/")
			target := domain.OperationTarget{Kind: domain.OperationTargetKind(kind), ID: id}
			operation := domain.OperationCode(request.Resource.Operation)
			if request.Resource.Confirmation == "plan" {
				plan, err := application.CreateHeadscaleLifecyclePlan(ctx, actor, operation, target, payload, nil)
				if err != nil {
					return ExecutionResult{}, err
				}
				result.PlanID, result.ExposureSummary, result.Prerequisites, result.ExpiresAt = plan.ID, plan.ExposureSummary, plan.Prerequisites, plan.ExpiresAt
				return ExecutionResult{ResultDigest: digestString(plan.ID), Headscale: result}, nil
			}
			if operation == domain.OperationPreauthKeyRevoke {
				value, err := application.RevokeHeadscalePreauthKey(ctx, actor, target, payload, nil)
				if err != nil {
					return ExecutionResult{}, err
				}
				key := helperKey(value.Key)
				result.JobID, result.Key = value.JobID, &key
			} else {
				value, err := application.ExpireHeadscaleDevice(ctx, actor, target, payload, nil)
				if err != nil {
					return ExecutionResult{}, err
				}
				device := helperDevice(value.Device)
				result.JobID, result.Device = value.JobID, &device
			}
		default:
			return ExecutionResult{}, fmt.Errorf("headscale mutation operation unavailable")
		}
		return ExecutionResult{ResultDigest: digestString(result.JobID), Headscale: result}, nil
	})
	preauthPlanHandler := PreauthKeyPlanHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil {
			return fmt.Errorf("preauth key Plan caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("preauth key Plan payload invalid")
		}
		var payload application.HeadscaleLifecyclePayload
		if err := decodeHeadscalePayload(request.Resource.Resource, &payload); err != nil {
			return ExecutionResult{}, err
		}
		if payload.ExpirationSeconds == 0 {
			payload.ExpirationSeconds = 3600
		}
		_, id, _ := strings.Cut(request.Target, "/")
		target := domain.OperationTarget{Kind: domain.OperationTargetHeadscaleUser, ID: id}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		plan, err := application.CreateHeadscaleLifecyclePlan(ctx, actor, domain.OperationPreauthKeyCreate, target, payload, nil)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: digestString(plan.ID), Headscale: &helperproto.HeadscaleResult{Operation: string(domain.OperationPreauthKeyCreate), PlanID: plan.ID, ExposureSummary: plan.ExposureSummary, Prerequisites: plan.Prerequisites, ExpiresAt: plan.ExpiresAt}}, nil
	})
	preauthCreateHandler := PreauthKeyCreateHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil {
			return fmt.Errorf("preauth key create caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("preauth key create payload invalid")
		}
		var payload application.HeadscaleLifecyclePayload
		if err := decodeHeadscalePayload(request.Resource.Resource, &payload); err != nil {
			return ExecutionResult{}, err
		}
		_, id, _ := strings.Cut(request.Target, "/")
		target := domain.OperationTarget{Kind: domain.OperationTargetHeadscaleUser, ID: id}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		value, err := application.CreateHeadscalePreauthKey(ctx, actor, target, payload, nil)
		if err != nil {
			return ExecutionResult{}, err
		}
		output, err := helperproto.NewOutputSecret(value.Secret)
		clear(value.Secret)
		if err != nil {
			return ExecutionResult{}, err
		}
		key := helperKey(value.Key)
		return ExecutionResult{ResultDigest: digestString(value.JobID), Secret: output, Headscale: &helperproto.HeadscaleResult{Operation: string(domain.OperationPreauthKeyCreate), JobID: value.JobID, Key: &key}}, nil
	})
	connectorMutationHandler := ConnectorMutationHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Target != "connector" {
			return fmt.Errorf("connector binding caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("connector binding payload invalid")
		}
		var payload application.ConnectorBindingPayload
		if err := decodeHeadscalePayload(request.Resource.Resource, &payload); err != nil {
			return ExecutionResult{}, err
		}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		value, err := application.SetConnectorBinding(ctx, actor, payload)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: digestString(value.JobID), Connector: &helperproto.ConnectorResult{Operation: string(domain.OperationConnectorBindingSet), JobID: value.JobID}}, nil
	})
	connectorReadHandler := ConnectorReadHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Target != "connector" {
			return fmt.Errorf("connector verify caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("connector verify carried secret")
		}
		value, err := application.VerifyConnector(ctx, nil, nil)
		if err != nil {
			return ExecutionResult{}, err
		}
		result := helperConnectorObservation(value.Observation)
		return ExecutionResult{ResultDigest: digestString(managedconnector.RedactedSummary(value.Observation)), Connector: &result}, nil
	})
	connectorPlanHandler := ConnectorLoginPlanHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Target != "connector" {
			return fmt.Errorf("connector login Plan caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("connector login Plan carried secret")
		}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		plan, err := application.CreateConnectorLoginPlan(ctx, actor)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: digestString(plan.ID), Connector: &helperproto.ConnectorResult{Operation: string(domain.OperationConnectorLogin), PlanID: plan.ID, ExposureSummary: plan.ExposureSummary, Prerequisites: plan.Prerequisites, ExpiresAt: plan.ExpiresAt}}, nil
	})
	connectorLoginHandler := ConnectorLoginHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Target != "connector" {
			return fmt.Errorf("connector login caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret == nil {
			return ExecutionResult{}, fmt.Errorf("connector login auth key missing")
		}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		payload := application.ConnectorLoginPayload{PlanID: request.Resource.PlanID, Confirmation: request.Resource.Confirmation}
		login := func(loginCtx context.Context, jobID, controlURL string) error {
			runner, uid, gid, err := application.OpenConnectorRuntime()
			if err != nil {
				return err
			}
			return secret.Use(func(value []byte) error {
				return runConnectorLoginSecret(loginCtx, runner, uid, gid, jobID, controlURL, value)
			})
		}
		value, err := application.ExecuteConnectorLogin(ctx, actor, payload, login, nil, nil)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: digestString(value.JobID), Connector: &helperproto.ConnectorResult{Operation: string(domain.OperationConnectorLogin), JobID: value.JobID}}, nil
	})
	resourceDeleteHandler := ResourceDeleteHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || !strings.HasPrefix(request.Target, "resource/") {
			return fmt.Errorf("resource delete caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("resource delete payload invalid")
		}
		id := strings.TrimPrefix(request.Target, "resource/")
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		value, err := application.DeleteResource(ctx, actor, domain.OperationTarget{Kind: domain.OperationTargetResource, ID: id}, application.ConfirmationPayload{PlanID: request.Resource.PlanID, Confirmation: request.Resource.Confirmation})
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: digestString(value.JobID), Action: &helperproto.ActionResult{JobID: value.JobID}}, nil
	})
	productReadHandler := ProductReadHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil {
			return fmt.Errorf("product read caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("product read payload invalid")
		}
		var value any
		var err error
		switch request.Resource.Operation {
		case string(domain.OperationStatus):
			if strings.HasPrefix(request.Target, "resource/") {
				value, err = application.ObserveDomainLiveSources(strings.TrimPrefix(request.Target, "resource/"))
			} else {
				value, err = application.ReadSystemStatus(ctx)
			}
		case string(domain.OperationDiagnostics):
			value, err = application.ReadDiagnostics(ctx)
		case string(domain.OperationConfigurationExport):
			value, err = application.ExportConfiguration(ctx)
		case string(domain.OperationJobList):
			value, err = application.ListJobs(ctx)
		case string(domain.OperationJobDetail):
			value, err = application.ReadJob(ctx, strings.TrimPrefix(request.Target, "job/"))
		default:
			return ExecutionResult{}, fmt.Errorf("product read operation unavailable")
		}
		if err != nil {
			return ExecutionResult{}, err
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: digestString(request.Resource.Operation + "/" + request.Target), Read: &helperproto.ReadResult{Operation: request.Resource.Operation, Payload: raw}}, nil
	})
	resourceMutationHandler := ResourceMutationHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Action != nil {
			return fmt.Errorf("resource mutation caller is unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("resource mutation carried secret or omitted payload")
		}
		actor := application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}
		secretDigests, err := secrets.KnownHostSecretDigests()
		if err != nil {
			return ExecutionResult{}, err
		}
		var candidate domain.AppResource
		var execution *application.ResourceExecution
		switch request.Resource.Operation {
		case "resource_create":
			if request.Target != "installation" {
				return ExecutionResult{}, fmt.Errorf("resource create target is invalid")
			}
			var kind struct {
				TargetKind domain.AppTargetKind `json:"target_kind"`
			}
			_ = json.Unmarshal(request.Resource.Resource, &kind)
			if kind.TargetKind == domain.AppTargetTailnetHTTP {
				var spec resource.TailnetSpec
				decoder := json.NewDecoder(bytes.NewReader(request.Resource.Resource))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&spec); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
					return ExecutionResult{}, fmt.Errorf("tailnet resource create payload is invalid")
				}
				candidate, err = resource.NewTailnet(spec, nil)
			} else {
				var spec resource.LocalSpec
				decoder := json.NewDecoder(bytes.NewReader(request.Resource.Resource))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&spec); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
					return ExecutionResult{}, fmt.Errorf("resource create payload is invalid")
				}
				candidate, err = resource.NewLocal(spec, nil)
			}
			if err == nil && candidate.ManagedProcess != nil {
				err = resource.ValidateArguments(candidate.ManagedProcess.Service.Arguments, secretDigests)
			}
			if err == nil {
				execution, err = application.BeginResourceCreate(ctx, actor, candidate)
			}
		case "resource_update":
			var marker struct {
				SchemaVersion string `json:"schema_version"`
			}
			_ = json.Unmarshal(request.Resource.Resource, &marker)
			if marker.SchemaVersion == application.DomainPublicationUpdateSchema {
				var update application.DomainPublicationUpdate
				decoder := json.NewDecoder(bytes.NewReader(request.Resource.Resource))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&update); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
					return ExecutionResult{}, fmt.Errorf("domain publication update payload invalid")
				}
				candidate, err = application.DomainPublicationCandidate(update)
			} else {
				decoder := json.NewDecoder(bytes.NewReader(request.Resource.Resource))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&candidate); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
					return ExecutionResult{}, fmt.Errorf("resource update payload is invalid")
				}
			}
			if err != nil {
				return ExecutionResult{}, err
			}
			if request.Target != "resource/"+candidate.ID {
				return ExecutionResult{}, fmt.Errorf("resource update target is invalid")
			}
			if candidate.ManagedProcess != nil {
				err = resource.ValidateArguments(candidate.ManagedProcess.Service.Arguments, secretDigests)
			}
			if err == nil {
				execution, err = application.BeginResourceUpdate(ctx, actor, candidate, secretDigests)
			}
		default:
			return ExecutionResult{}, fmt.Errorf("resource mutation operation is invalid")
		}
		if err != nil {
			return ExecutionResult{}, err
		}
		defer func() { _ = execution.Close() }()
		if request.Resource.Operation == "resource_create" {
			_, err = execution.CommitCreate(ctx)
		} else {
			_, err = execution.CommitUpdate(ctx)
		}
		if err != nil {
			_ = unix.Kill(os.Getpid(), unix.SIGTERM)
			return ExecutionResult{}, err
		}
		digest, err := resource.ConfigDigest(candidate)
		return ExecutionResult{ResultDigest: digest, Resource: &helperproto.ResourceResult{ResourceID: candidate.ID}}, err
	})
	processHandler := ProcessLifecycleHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Action != nil || !strings.HasPrefix(request.Target, "resource/") {
			return fmt.Errorf("process lifecycle caller is unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (output ExecutionResult, resultErr error) {
		if secret != nil || request.Resource == nil {
			return ExecutionResult{}, fmt.Errorf("process lifecycle carried secret or omitted payload")
		}
		resourceID := strings.TrimPrefix(request.Target, "resource/")
		start := request.Resource.Operation == "process_start"
		if !start && request.Resource.Operation != "process_stop" {
			return ExecutionResult{}, fmt.Errorf("process lifecycle operation invalid")
		}
		execution, err := application.BeginProcess(ctx, application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}, resourceID, start)
		if err != nil {
			return ExecutionResult{}, err
		}
		host, err := managedprocess.NewFixedHost()
		if err != nil {
			commitErr := execution.CommitNoEffect(ctx)
			closeErr := execution.Close()
			if commitErr != nil || closeErr != nil {
				_ = unix.Kill(os.Getpid(), unix.SIGTERM)
			}
			return ExecutionResult{}, errors.Join(err, commitErr, closeErr)
		}
		journal := managedprocess.Journal{SchemaVersion: "lanpanel.process.lifecycle.v1", JobID: execution.JobID, ResourceID: resourceID, Operation: request.Resource.Operation, Phase: "prepared", Applied: execution.Resource.ManagedProcess.Applied}
		if start {
			journal.RelayRequired = execution.Resource.Target.LocalHTTP.EndpointKind == domain.LocalEndpointRelayUnix
		} else if journal.Applied != nil {
			journal.RelayRequired = journal.Applied.RelayRequired
		}
		if journal.Applied != nil {
			journal.BundleDigest = journal.Applied.PolicyDigest
			journal.ApplicationUID = journal.Applied.ApplicationUID
			journal.ApplicationGID = journal.Applied.ApplicationGID
			journal.RelayUID = journal.Applied.RelayUID
			journal.RelayGID = journal.Applied.RelayGID
		}
		if err := managedprocess.WriteJournal(ctx, journal); err != nil {
			closeErr := execution.Close()
			_ = unix.Kill(os.Getpid(), unix.SIGTERM)
			return ExecutionResult{}, errors.Join(err, closeErr)
		}
		journalActive, terminalCommitted, outcomeUncertain := true, false, false
		defer func() {
			if resultErr == nil || !journalActive {
				return
			}
			if terminalCommitted || outcomeUncertain {
				closeErr := execution.Close()
				_ = unix.Kill(os.Getpid(), unix.SIGTERM)
				resultErr = errors.Join(resultErr, closeErr)
				return
			}
			recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			var stopErr error
			if !start || journal.Phase != "prepared" {
				stopErr = host.Stop(recoveryCtx, resourceID, journal.RelayRequired)
			}
			var commitErr, verifyErr, closeErr, removeErr error
			if stopErr == nil {
				commitErr = execution.CommitInterrupted(recoveryCtx, journal.Applied)
			}
			if stopErr == nil && commitErr == nil {
				verifyErr = host.VerifyCommittedJournal(recoveryCtx, journal, false)
			}
			if stopErr == nil && commitErr == nil && verifyErr == nil {
				closeErr = execution.Close()
			}
			if stopErr == nil && commitErr == nil && verifyErr == nil && closeErr == nil {
				removeErr = managedprocess.RemoveJournal(resourceID)
			}
			if stopErr != nil || commitErr != nil || verifyErr != nil || closeErr != nil || removeErr != nil {
				_ = unix.Kill(os.Getpid(), unix.SIGTERM)
			} else {
				journalActive = false
			}
			resultErr = errors.Join(resultErr, stopErr, commitErr, verifyErr, closeErr, removeErr)
		}()
		if start {
			if execution.Resource.ManagedProcess.Requested == domain.ProcessRequestedRunning {
				return ExecutionResult{}, fmt.Errorf("managed process is already requested running; stop before applying changed service configuration")
			}
			installationID := execution.Service.NormalInstallationID()
			if installationID == "" {
				return ExecutionResult{}, fmt.Errorf("installation identity unavailable")
			}
			relayRequired := execution.Resource.Target.LocalHTTP.EndpointKind == domain.LocalEndpointRelayUnix
			accounts, err := identity.ResourceAccounts(installationID, resourceID, relayRequired)
			if err != nil {
				return ExecutionResult{}, err
			}
			accounts, _, err = host.InstallAccounts(ctx, accounts)
			if err != nil {
				return ExecutionResult{}, err
			}
			profile, err := managedprocess.LoadConfinementProfile()
			if err != nil {
				return ExecutionResult{}, err
			}
			secretDigests, err := secrets.KnownHostSecretDigests()
			if err != nil {
				return ExecutionResult{}, err
			}
			evidence, err := resource.ValidateServiceReferences(execution.Resource.ManagedProcess.Service, accounts.Identities[0].UID, secretDigests)
			if err != nil {
				return ExecutionResult{}, err
			}
			binding := execution.Resource.ManagedProcess.ReferenceBinding
			if binding != nil {
				if binding.ExecutableDigest != evidence.ExecutableDigest || binding.WorkingDirectoryIdentity != evidence.WorkingDirectoryIdentity || binding.EnvironmentFingerprint != evidence.EnvironmentFingerprint || !slices.Equal(binding.WritePathIdentities, evidence.WritePathIdentities) {
					return ExecutionResult{}, fmt.Errorf("managed process references differ from explicit stopped reapply binding")
				}
			} else if applied := execution.Resource.ManagedProcess.Applied; applied != nil && (applied.ExecutableDigest != evidence.ExecutableDigest || applied.WorkingDirectoryIdentity != evidence.WorkingDirectoryIdentity || applied.EnvironmentFingerprint != evidence.EnvironmentFingerprint || !slices.Equal(applied.WritePathIdentities, evidence.WritePathIdentities)) {
				return ExecutionResult{}, fmt.Errorf("managed process external reference drift requires explicit stopped resource update")
			}
			startResource := execution.Resource
			startProcess := *startResource.ManagedProcess
			startProcess.Requested = domain.ProcessRequestedRunning
			startResource.ManagedProcess = &startProcess
			nginxGID, groupErr := lookupGroupGID("www-data")
			if groupErr != nil {
				return ExecutionResult{}, groupErr
			}
			units, err := managedprocess.Render(installationID, startResource, accounts, profile, evidence, nginxGID)
			if err != nil {
				return ExecutionResult{}, err
			}
			if _, err := host.Install(ctx, resourceID, units); err != nil {
				return ExecutionResult{}, err
			}
			journal.Phase = "activating"
			journal.BundleDigest = units.Bundle.PolicyDigest
			journal.RelayRequired = relayRequired
			journal.Applied = &units.Bundle
			journal.Policy = units.Confinement
			journal.ApplicationUID = units.ApplicationUID
			journal.ApplicationGID = units.ApplicationGID
			journal.RelayUID = units.RelayUID
			journal.RelayGID = units.RelayGID
			if err := managedprocess.WriteJournal(ctx, journal); err != nil {
				return ExecutionResult{}, err
			}
			contractFailure := func(cause error) (ExecutionResult, error) { return ExecutionResult{}, cause }
			if err := host.Start(ctx, resourceID, units); err != nil {
				return contractFailure(err)
			}
			journal.Phase = "host_mutated"
			if err := managedprocess.WriteJournal(ctx, journal); err != nil {
				return contractFailure(err)
			}
			observation, err := managedprocess.Observe(ctx, "/sys/fs/cgroup", units.Bundle, execution.Resource.Target.LocalHTTP.EndpointKind, []string{"/proc/net/tcp", "/proc/net/tcp6"})
			verifyErr := managedprocess.VerifyRunning(observation)
			if err != nil || verifyErr != nil {
				return contractFailure(fmt.Errorf("managed process start observation failed: %w", errors.Join(err, verifyErr)))
			}
			job, err := execution.Commit(ctx, &units.Bundle, observation)
			if err != nil {
				committed, outcomeErr := execution.CommitSucceeded(journal)
				if committed {
					terminalCommitted = true
				} else if outcomeErr != nil {
					outcomeUncertain = true
				}
				return contractFailure(errors.Join(err, outcomeErr))
			}
			terminalCommitted = true
			if err := execution.Close(); err != nil {
				return ExecutionResult{}, err
			}
			if err := managedprocess.RemoveJournal(resourceID); err != nil {
				return ExecutionResult{}, err
			}
			journalActive = false
			return ExecutionResult{ResultDigest: observation.Digest, Action: &helperproto.ActionResult{JobID: job.ID}}, nil
		}
		bundle := execution.Resource.ManagedProcess.Applied
		if bundle == nil {
			return ExecutionResult{}, fmt.Errorf("managed process stop lacks applied bundle authority")
		}
		if err := host.Stop(ctx, resourceID, bundle.RelayRequired); err != nil {
			return ExecutionResult{}, err
		}
		finishStoppedFailure := func(cause error) (ExecutionResult, error) { return ExecutionResult{}, cause }
		journal.Phase = "host_mutated"
		journal.BundleDigest = bundle.PolicyDigest
		journal.RelayRequired = bundle.RelayRequired
		if err := managedprocess.WriteJournal(ctx, journal); err != nil {
			return finishStoppedFailure(err)
		}
		observation, err := managedprocess.ObserveStopped(ctx, "/sys/fs/cgroup", *bundle)
		if err != nil {
			return finishStoppedFailure(err)
		}
		job, err := execution.Commit(ctx, bundle, observation)
		if err != nil {
			committed, outcomeErr := execution.CommitSucceeded(journal)
			if committed {
				terminalCommitted = true
			} else if outcomeErr != nil {
				outcomeUncertain = true
			}
			return finishStoppedFailure(errors.Join(err, outcomeErr))
		}
		terminalCommitted = true
		if err := host.VerifyCommittedJournal(ctx, journal, false); err != nil {
			return ExecutionResult{}, err
		}
		if err := execution.Close(); err != nil {
			return ExecutionResult{}, err
		}
		if err := managedprocess.RemoveJournal(resourceID); err != nil {
			return ExecutionResult{}, err
		}
		journalActive = false
		return ExecutionResult{ResultDigest: observation.Digest, Action: &helperproto.ActionResult{JobID: job.ID}}, nil
	})
	publicationHandler := PublicationActivateHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Resource == nil || request.Resource.Operation != "publish" || !strings.HasPrefix(request.Target, "resource/") {
			return fmt.Errorf("publication caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (output ExecutionResult, resultErr error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("publication carried secret")
		}
		kind, err := application.CurrentPublicationKind(request.Target)
		if err != nil {
			return ExecutionResult{}, err
		}
		if kind == domain.PublicationDomainHTTPS {
			return executeDomainPublication(ctx, request)
		}
		if kind != domain.PublicationTemporaryHTTP {
			return ExecutionResult{}, fmt.Errorf("publication type unsupported")
		}
		execution, err := application.BeginPublication(ctx, application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}, request.Target, application.ConfirmationPayload{PlanID: request.Resource.PlanID, Confirmation: request.Resource.Confirmation})
		if err != nil {
			return ExecutionResult{}, err
		}
		defer func() {
			closeErr := execution.Close()
			if resultErr != nil && closeErr != nil {
				resultErr = errors.Join(resultErr, closeErr)
			}
		}()
		job, err := execution.Run(ctx)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: execution.Candidate.BundleDigest, Action: &helperproto.ActionResult{JobID: job.ID, JobResult: string(job.Result), PublicURL: execution.Candidate.PublicURL}}, nil
	})
	managedBasicHandler := ManagedBasicGenerateHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Action == nil {
			return fmt.Errorf("managed Basic caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("managed Basic request carried secret")
		}
		actor := fmt.Sprintf("ui/%s/generation/%d", request.Action.ActorIdentity, request.Action.ActorGeneration)
		var result application.ManagedBasicResult
		var err error
		if request.Action.Operation == "managed_basic_create" {
			result, err = application.CreateManagedBasic(ctx, request.Action.TargetID, request.Action.Username, actor)
		} else {
			result, err = application.RotateManagedBasic(ctx, request.Action.TargetID, actor)
		}
		if err != nil {
			return ExecutionResult{}, err
		}
		defer clear(result.Password)
		output, err := helperproto.NewOutputSecret(result.Password)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: result.Fingerprint, Secret: output, Action: &helperproto.ActionResult{JobID: result.Job.ID, Operation: request.Action.Operation, TargetKind: "credential", TargetID: result.CredentialID}}, nil
	})
	staticRootHandler := StaticRootRegisterHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Action == nil {
			return fmt.Errorf("static root caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("static root carried secret")
		}
		actor := fmt.Sprintf("ui/%s/generation/%d", request.Action.ActorIdentity, request.Action.ActorGeneration)
		result, err := application.RegisterStaticRoot(ctx, request.Action.TargetID, request.Action.StaticRoot, actor)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: result.Root.Fingerprint, Action: &helperproto.ActionResult{JobID: result.Job.ID, Operation: "static_root_register", TargetKind: "static", TargetID: result.Root.ID}}, nil
	})
	externalHTPasswdHandler := ExternalHTPasswdRegisterHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Action == nil {
			return fmt.Errorf("external htpasswd caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("external htpasswd carried secret")
		}
		actor := fmt.Sprintf("ui/%s/generation/%d", request.Action.ActorIdentity, request.Action.ActorGeneration)
		result, err := application.RegisterExternalHTPasswd(ctx, request.Action.TargetID, request.Action.ExternalHTPasswdFile, actor)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: result.Fingerprint, Action: &helperproto.ActionResult{JobID: result.Job.ID, Operation: "external_htpasswd_register", TargetKind: "credential", TargetID: result.CredentialID}}, nil
	})
	domainStatusHandler := DomainStatusHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Action == nil {
			return fmt.Errorf("domain status caller unauthorized")
		}
		return nil
	}, func(_ context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("domain status carried secret")
		}
		status, err := application.ObserveDomainLiveSources(request.Action.TargetID)
		if err != nil {
			return ExecutionResult{}, err
		}
		raw, _ := json.Marshal(status)
		return ExecutionResult{ResultDigest: digestString(string(raw)), Resource: &helperproto.ResourceResult{ResourceID: status.ResourceID, Status: status.Status, AccessMayRemain: status.AccessMayRemain, CredentialID: status.CredentialID, CredentialFingerprint: status.CredentialFingerprint, CredentialChanged: status.CredentialChanged, GoAccessCredentialID: status.GoAccessCredentialID, GoAccessCredentialFingerprint: status.GoAccessCredentialFingerprint, GoAccessCredentialChanged: status.GoAccessCredentialChanged, StaticFingerprint: status.StaticFingerprint, StaticChanged: status.StaticChanged, ObservedAt: status.ObservedAt, Reason: status.Reason, AllowedActions: append([]string(nil), status.AllowedActions...), CredentialIDs: append([]string(nil), status.CredentialIDs...), GoAccessRetirementJobID: status.GoAccessRetirementJobID, GoAccessRetirementGenerations: append([]uint64(nil), status.GoAccessRetirementGenerations...)}}, nil
	})
	managedBasicDeleteHandler := ManagedBasicDeleteHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Action == nil {
			return fmt.Errorf("managed Basic delete caller unauthorized")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("managed Basic delete carried secret")
		}
		actor := fmt.Sprintf("ui/%s/generation/%d", request.Action.ActorIdentity, request.Action.ActorGeneration)
		record, err := application.DeleteManagedBasic(ctx, request.Action.TargetID, actor, request.Action.PlanID)
		if err != nil {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: digestString(request.Action.TargetID), Action: &helperproto.ActionResult{JobID: record.ID, Operation: "managed_basic_delete", TargetKind: "credential", TargetID: request.Action.TargetID}}, nil
	})
	renewalHandler := CertificateRenewHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerTimer || request.Target != "installation" {
			return fmt.Errorf("certificate renewal requires timer installation tick")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, _ helperproto.Request, _ *helperproto.Secret) (ExecutionResult, error) {
		return executeCertificateTimer(ctx)
	})
	profileHandler := ManagementProfileHandler(authRevalidate, func(_ context.Context, _ helperproto.Caller, _ helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("management profile request carried secret")
		}
		tokenMu.Lock()
		profile := managementProfileWithRecovery(errors.Join(adminRecoveryErr, otherRecoveryErr))
		tokenMu.Unlock()
		return ExecutionResult{ResultDigest: profileDigest(profile)}, nil
	})
	mutationGate := func(request helperproto.Request) error {
		tokenMu.Lock()
		recoveryErr := errors.Join(adminRecoveryErr, otherRecoveryErr)
		tokenMu.Unlock()
		if recoveryErr == nil {
			return nil
		}
		switch request.Operation {
		case helperproto.OperationAdminTokenVerify, helperproto.OperationAdminTokenSource, helperproto.OperationManagementProfile, helperproto.OperationAdminTokenReconcile, helperproto.OperationDomainStatus, helperproto.OperationHeadscaleRead, helperproto.OperationConnectorRead, helperproto.OperationProductRead, helperproto.OperationContractionClose, helperproto.OperationStartupContraction:
			return nil
		case helperproto.OperationApplicationPlan:
			if request.Action != nil && (request.Action.Operation == "close_all" || request.Action.Operation == "unpublish") {
				return nil
			}
		}
		return fmt.Errorf("startup recovery is incomplete")
	}
	server, err := NewServer(config.Identities, []Registration{applicationHandler, verifyHandler, sourceHandler, rotateHandler, reconcileHandler, contractionHandler, startupHandler, headscaleHandler, headscaleReadHandler, headscaleMutationHandler, preauthPlanHandler, preauthCreateHandler, connectorMutationHandler, connectorReadHandler, connectorPlanHandler, connectorLoginHandler, resourceDeleteHandler, productReadHandler, resourceMutationHandler, processHandler, publicationHandler, managedBasicHandler, managedBasicDeleteHandler, staticRootHandler, externalHTPasswdHandler, domainStatusHandler, headscaleDeployHandler, headscaleReissueHandler, renewalHandler, profileHandler}, Options{MutationGate: mutationGate})
	if err != nil {
		return err
	}
	listener, err := ListenProtected(config.SocketGroup)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(listener.Close)
	if err := notifyReady(); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return server.Serve(ctx, listener)
}

func reconcileStartupContraction(ctx context.Context) error {
	if normal, err := application.OpenFixed(); err == nil {
		allowed, guardErr := normal.NginxStartAllowed(time.Now().UTC())
		publicationErr := normal.PendingPublicationRecovery()
		_ = normal.Close()
		if guardErr == nil && publicationErr == nil && allowed {
			return nil
		}
	}
	service, err := contraction.OpenEmergency(ctx)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	snapshot, err := service.Snapshot()
	if err != nil {
		return err
	}
	if err := service.RecoverClosed(ctx, snapshot.GlobalGeneration, snapshot.Inventory.Digest); err == nil {
		return nil
	}
	result, runErr := service.Run(ctx, snapshot.GlobalGeneration, snapshot.Inventory.Digest)
	if result.Outcome == contraction.OutcomePartial || result.Outcome == contraction.OutcomeUnknown {
		return errors.Join(runErr, fmt.Errorf("startup contraction did not converge: %s", result.Outcome))
	}
	return runErr
}

func lookupGroupGID(name string) (uint32, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 4 && fields[0] == name {
			value, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil || value == 0 {
				return 0, fmt.Errorf("fixed group identity is invalid")
			}
			return uint32(value), nil
		}
	}
	return 0, fmt.Errorf("fixed group identity is missing")
}

func cleanupConnectorLoginSecrets() error {
	authorities, err := application.ConnectorLoginTempAuthorities()
	if err != nil {
		return err
	}
	_, uid, gid, err := application.OpenConnectorRuntime()
	if err != nil {
		return err
	}
	directory, err := unix.Open("/var/lib/lanpanel/connector/auth", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(directory) }()
	var stat unix.Stat_t
	if err := unix.Fstat(directory, &stat); err != nil || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != 0o700 {
		return fmt.Errorf("connector auth temp directory is unsafe")
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", directory))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".key") {
			return fmt.Errorf("connector auth directory contains foreign member")
		}
		jobID := strings.TrimSuffix(name, ".key")
		if !authorities[jobID] {
			return fmt.Errorf("connector auth temp file lacks exact job authority")
		}
		var item unix.Stat_t
		if err := unix.Fstatat(directory, name, &item, unix.AT_SYMLINK_NOFOLLOW); err != nil || item.Mode&unix.S_IFMT != unix.S_IFREG || item.Mode&0o7777 != 0o600 || item.Uid != uid || item.Gid != gid || item.Nlink != 1 {
			return fmt.Errorf("connector auth temp file is unsafe")
		}
		if err := unix.Unlinkat(directory, name, 0); err != nil {
			return err
		}
	}
	return unix.Fsync(directory)
}

func helperConnectorObservation(value managedconnector.Observation) helperproto.ConnectorResult {
	local, peers := make([]string, len(value.LocalIPs)), make([]string, len(value.Peers))
	for index, address := range value.LocalIPs {
		local[index] = address.String()
	}
	for index, peer := range value.Peers {
		peers[index] = peer.IP.String()
	}
	slices.Sort(local)
	slices.Sort(peers)
	return helperproto.ConnectorResult{Operation: string(domain.OperationConnectorVerify), ClientVersion: value.ClientVersion, ControlURL: value.ControlURL, LocalIPs: local, PeerIPs: peers, ValidUntil: value.ValidUntil}
}

func runConnectorLoginSecret(ctx context.Context, runner managedconnector.Runner, uid, gid uint32, jobID, controlURL string, secret []byte) (returnErr error) {
	if runner == nil || uid == 0 || gid == 0 || !strings.HasPrefix(jobID, "job_") || len(jobID) != 68 || len(secret) < 16 || len(secret) > 4096 || connectorSecretHasSeparator(secret) {
		return fmt.Errorf("connector login secret authority invalid")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(jobID, "job_")); err != nil {
		return fmt.Errorf("connector login job ID invalid")
	}
	parent, err := unix.Open("/var/lib/lanpanel", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	if err := ensureConnectorDirectory(parent, "connector", 0, 0, 0o711); err != nil {
		return err
	}
	connectorFD, err := unix.Openat(parent, "connector", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(connectorFD) }()
	if err := ensureConnectorDirectory(connectorFD, "auth", uid, gid, 0o700); err != nil {
		return err
	}
	authFD, err := unix.Openat(connectorFD, "auth", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(authFD) }()
	name := jobID + ".key"
	fd, err := unix.Openat(authFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() error {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		unlinkErr := unix.Unlinkat(authFD, name, 0)
		syncErr := unix.Fsync(authFD)
		var stat unix.Stat_t
		absenceErr := unix.Fstatat(authFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if absenceErr == nil {
			return errors.Join(unlinkErr, syncErr, fmt.Errorf("connector auth key temp file remains"))
		}
		if !errors.Is(absenceErr, unix.ENOENT) {
			return errors.Join(unlinkErr, syncErr, absenceErr)
		}
		return errors.Join(unlinkErr, syncErr)
	}
	defer func() { returnErr = errors.Join(returnErr, cleanup()) }()
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return err
	}
	written := 0
	for written < len(secret) {
		n, writeErr := unix.Write(fd, secret[written:])
		if writeErr != nil {
			return writeErr
		}
		if n == 0 {
			return fmt.Errorf("short connector auth key write")
		}
		written += n
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	fd = -1
	return managedconnector.Login(ctx, runner, controlURL, "/var/lib/lanpanel/connector/auth/"+name)
}

func connectorSecretHasSeparator(value []byte) bool {
	for _, character := range value {
		switch character {
		case 0, '\r', '\n', ' ', '\t':
			return true
		}
	}
	return false
}

func ensureConnectorDirectory(parent int, name string, uid, gid uint32, mode uint32) error {
	if err := unix.Mkdirat(parent, name, mode); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid == 0 && stat.Gid == 0 && (uid != 0 || gid != 0) {
		if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
			return err
		}
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode {
		return fmt.Errorf("connector auth directory metadata is unsafe")
	}
	return unix.Fsync(parent)
}

func decodeHeadscalePayload(raw json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("headscale lifecycle payload is invalid")
	}
	return nil
}

func helperUser(value managedheadscale.User) helperproto.HeadscaleUserRecord {
	return helperproto.HeadscaleUserRecord{ID: value.ID, Name: value.Name, CreatedAt: value.CreatedAt, DeviceCount: value.DeviceCount, ActiveKeyCount: value.ActiveKeyCount}
}

func helperUsers(values []managedheadscale.User) []helperproto.HeadscaleUserRecord {
	result := make([]helperproto.HeadscaleUserRecord, len(values))
	for index, value := range values {
		result[index] = helperUser(value)
	}
	return result
}

func helperKey(value managedheadscale.PreauthKey) helperproto.HeadscaleKeyRecord {
	return helperproto.HeadscaleKeyRecord{ID: value.ID, UserID: value.UserID, Reusable: value.Reusable, Ephemeral: value.Ephemeral, Used: value.Used, Expiration: value.Expiration, CreatedAt: value.CreatedAt}
}

func helperKeys(values []managedheadscale.PreauthKey) []helperproto.HeadscaleKeyRecord {
	result := make([]helperproto.HeadscaleKeyRecord, len(values))
	for index, value := range values {
		result[index] = helperKey(value)
	}
	return result
}

func helperDevice(value managedheadscale.Device) helperproto.HeadscaleDeviceRecord {
	return helperproto.HeadscaleDeviceRecord{ID: value.ID, Name: value.Name, UserID: value.UserID, IPAddresses: append([]string(nil), value.IPAddresses...), Online: value.Online, Expiry: value.Expiry, CreatedAt: value.CreatedAt}
}

func helperDevices(values []managedheadscale.Device) []helperproto.HeadscaleDeviceRecord {
	result := make([]helperproto.HeadscaleDeviceRecord, len(values))
	for index, value := range values {
		result[index] = helperDevice(value)
	}
	return result
}

func digestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func executeDomainPublication(ctx context.Context, request helperproto.Request) (output ExecutionResult, resultErr error) {
	execution, err := application.BeginCertificateIssue(ctx, application.Actor{Kind: application.ActorUI, Identity: request.Resource.ActorIdentity, Generation: request.Resource.ActorGeneration}, request.Target, application.ConfirmationPayload{PlanID: request.Resource.PlanID, Confirmation: request.Resource.Confirmation})
	if err != nil {
		return ExecutionResult{}, err
	}
	defer func() {
		if closeErr := execution.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	abort := func(cause error) (ExecutionResult, error) {
		return ExecutionResult{}, execution.Abort(context.WithoutCancel(ctx), cause)
	}
	if err := execution.ActivateChallenge(ctx); err != nil {
		return abort(err)
	}
	result, runErr := execution.RunRemote(ctx, execution.StageUID, execution.StageGID)
	if err := execution.TerminalizeChild(ctx, result, runErr); err != nil {
		return abort(err)
	}
	if runErr != nil {
		return abort(runErr)
	}
	material, err := execution.LoadIssued(time.Now().UTC())
	if err != nil {
		return abort(err)
	}
	identity, err := certificates.StageIssued(ctx, certificates.FixedBundlesRoot, execution.Challenge.Safety.CertificateIdentity, execution.BundleGeneration, execution.Child.InputDigest, material, filetxn.Owner{UID: execution.StageUID, GID: execution.StageGID}, time.Now().UTC())
	if err != nil {
		return abort(err)
	}
	certificate, err := execution.PreparePublicationCertificate(ctx, identity)
	if err != nil {
		return abort(err)
	}
	publicationExecution, err := execution.PrepareDomainPublication(ctx, certificate)
	if err != nil {
		return abort(err)
	}
	defer func() {
		if closeErr := publicationExecution.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	job, err := publicationExecution.Run(ctx)
	if err != nil {
		if job.ID == "" || job.Status != jobs.StatusTerminal || job.Result != jobs.ResultPartial {
			return ExecutionResult{}, err
		}
		return ExecutionResult{ResultDigest: publicationExecution.Candidate.BundleDigest, Action: &helperproto.ActionResult{JobID: job.ID, JobResult: string(job.Result), PublicURL: publicationExecution.Candidate.PublicURL}}, nil
	}
	return ExecutionResult{ResultDigest: publicationExecution.Candidate.BundleDigest, Action: &helperproto.ActionResult{JobID: job.ID, JobResult: string(job.Result), PublicURL: publicationExecution.Candidate.PublicURL}}, nil
}

func executeCertificateTimer(ctx context.Context) (ExecutionResult, error) {
	now := time.Now().UTC()
	independent := func(cause error) (ExecutionResult, error) {
		return ExecutionResult{}, errors.Join(cause, application.ContractIndependentCertificateExpiries(context.WithoutCancel(ctx), now))
	}
	service, err := application.OpenFixed()
	if err != nil {
		return independent(err)
	}
	if err := service.ObserveCertificateTrustedWall(ctx, now); err != nil {
		_ = service.Close()
		return independent(err)
	}
	state, err := service.SafetyState()
	if err != nil {
		_ = service.Close()
		return independent(err)
	}
	document, err := service.Normal().Read()
	if err != nil {
		_ = service.Close()
		return independent(err)
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		_ = service.Close()
		return independent(fmt.Errorf("installation authority missing"))
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		_ = service.Close()
		return independent(err)
	}
	headscaleDecision, decisionErr := renewal.EvaluateHeadscale(now, 30*24*time.Hour, installation.Headscale, state)
	if decisionErr != nil {
		_ = service.Close()
		return independent(decisionErr)
	}
	if state.Headscale.CertificateExpiry != nil {
		headscaleDecision = renewal.DecisionContract
	}
	decisions := map[string]renewal.Decision{}
	for _, resource := range installation.Resources {
		for _, safetyResource := range state.Resources {
			if safetyResource.ResourceID == resource.ID && safetyResource.CertificateExpiry != nil {
				decisions[resource.ID] = renewal.DecisionContract
			}
		}
		if decisions[resource.ID] == renewal.DecisionContract {
			continue
		}
		decision, decisionErr := renewal.Evaluate(renewal.Input{Now: now, RenewBefore: 30 * 24 * time.Hour, Publication: resource.PublicationRecord, Safety: state, ResourceID: resource.ID})
		if decisionErr != nil {
			_ = service.Close()
			return independent(decisionErr)
		}
		if decision != renewal.DecisionIdle {
			decisions[resource.ID] = decision
		}
	}
	if err := service.Close(); err != nil {
		return independent(err)
	}
	summary := strings.Builder{}
	switch headscaleDecision {
	case renewal.DecisionContract:
		if err := application.ContractExpiredHeadscaleCertificate(ctx, now); err != nil {
			return independent(err)
		}
		summary.WriteString("headscale:contracted;")
	case renewal.DecisionRenew:
		fingerprint, renewErr := application.ExecuteHeadscaleCertificateRenewal(ctx)
		if renewErr != nil {
			return independent(renewErr)
		}
		fmt.Fprintf(&summary, "headscale:renewed:%s;", fingerprint)
	}
	for _, resource := range installation.Resources {
		if decisions[resource.ID] != renewal.DecisionContract {
			continue
		}
		if err := application.ContractExpiredCertificate(ctx, resource.ID, now); err != nil {
			return independent(err)
		}
		fmt.Fprintf(&summary, "%s:contracted;", resource.ID)
	}
	for _, resource := range installation.Resources {
		if decisions[resource.ID] != renewal.DecisionRenew {
			continue
		}
		fingerprint, err := executeCertificateRenewal(ctx, resource.ID)
		if err != nil {
			return independent(err)
		}
		fmt.Fprintf(&summary, "%s:renewed:%s;", resource.ID, fingerprint)
		break
	}
	return ExecutionResult{ResultDigest: digestString(summary.String())}, nil
}

func executeCertificateRenewal(ctx context.Context, resourceID string) (string, error) {
	execution, err := application.BeginCertificateRenew(ctx, resourceID)
	if err != nil {
		return "", err
	}
	defer func(ignore func() error) { _ = ignore() }(execution.Close)
	abort := func(cause error) error { return execution.Abort(context.WithoutCancel(ctx), cause) }
	stageIdentity := child.Identity{UID: execution.StageUID, GID: execution.StageGID, Chroot: "/var/lib/lanpanel/certificates/chroot/" + execution.Challenge.Safety.CertificateIdentity}
	if err := execution.ActivateChallenge(ctx); err != nil {
		return "", abort(err)
	}
	result, runErr := execution.RunRemote(ctx, stageIdentity.UID, stageIdentity.GID)
	if err := execution.TerminalizeChild(ctx, result, runErr); err != nil {
		return "", abort(err)
	}
	if runErr != nil {
		return "", abort(runErr)
	}
	material, err := execution.LoadIssued(time.Now().UTC())
	if err != nil {
		return "", abort(err)
	}
	bundle, err := certificates.StageIssued(ctx, certificates.FixedBundlesRoot, execution.Challenge.Safety.CertificateIdentity, execution.BundleGeneration, execution.Child.InputDigest, material, filetxn.Owner{UID: stageIdentity.UID, GID: stageIdentity.GID}, time.Now().UTC())
	if err != nil {
		return "", abort(err)
	}
	if _, err := execution.CompleteRenewal(ctx, bundle); err != nil {
		return "", abort(err)
	}
	return bundle.Fingerprint, nil
}

func ReadIdentityConfig() (IdentityConfig, error) {
	parent := filepath.Dir(FixedIdentityConfigPath)
	if err := validateRootParentChain(parent, 0, 0o711); err != nil {
		return IdentityConfig{}, fmt.Errorf("helper identity parent chain: %w", err)
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return IdentityConfig{}, fmt.Errorf("open helper identity parent: %w", err)
	}
	defer func() { _ = unix.Close(parentFD) }()
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil || parentStat.Uid != 0 || parentStat.Gid != 0 || parentStat.Mode&0o777 != 0o711 {
		return IdentityConfig{}, fmt.Errorf("helper identity parent is not root-owned mode 0711")
	}
	fd, err := unix.Openat(parentFD, filepath.Base(FixedIdentityConfigPath), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return IdentityConfig{}, fmt.Errorf("open helper identity config: %w", err)
	}
	file := os.NewFile(uintptr(fd), "helper-identities")
	if file == nil {
		_ = unix.Close(fd)
		return IdentityConfig{}, fmt.Errorf("helper identity descriptor is invalid")
	}
	defer func(ignore func() error) { _ = ignore() }(file.Close)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Size <= 0 || stat.Size > maximumIdentityConfigBytes {
		return IdentityConfig{}, fmt.Errorf("helper identity config ownership, type, mode, link, or size is invalid")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximumIdentityConfigBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumIdentityConfigBytes {
		return IdentityConfig{}, fmt.Errorf("read bounded helper identity config")
	}
	var config IdentityConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return IdentityConfig{}, fmt.Errorf("decode helper identity config")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return IdentityConfig{}, fmt.Errorf("helper identity config has trailing data")
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, payload) || config.SchemaVersion != identityConfigSchema || config.SocketGroup == 0 {
		return IdentityConfig{}, fmt.Errorf("helper identity config is noncanonical or incomplete")
	}
	if err := validateIdentities(config.Identities); err != nil {
		return IdentityConfig{}, err
	}
	return config, nil
}
