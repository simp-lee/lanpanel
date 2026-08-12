//go:build linux

package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/application"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/packages"
	"lanpanel/internal/secrets"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const FixedIdentityConfigPath = "/var/lib/lanpanel/installation/helper-identities.json"
const identityConfigSchema = "lanpanel.helper.identities.v1"
const maximumIdentityConfigBytes = 4096

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
	if err := application.ReconcileAdminTokenRotation(context.Background(), fingerprint); err != nil {
		return fmt.Errorf("reconcile admin token rotation: %w", err)
	}
	var packageMu sync.Mutex
	var tokenMu sync.Mutex
	withPackageService := func(use func(*packages.Service) error) error {
		packageMu.Lock()
		defer packageMu.Unlock()
		service, err := packages.OpenFixedService()
		if err != nil {
			return fmt.Errorf("open fixed package transaction service: %w", err)
		}
		defer service.Close()
		return use(service)
	}
	applicationHandler := ApplicationPlanHandler(func(_ context.Context, caller helperproto.Caller, request helperproto.Request) error {
		if caller != helperproto.CallerUI || request.Action == nil {
			return fmt.Errorf("application caller invalid")
		}
		return nil
	}, func(ctx context.Context, _ helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("application request carried secret")
		}
		service, err := application.OpenFixed()
		if err != nil {
			return ExecutionResult{}, err
		}
		defer service.Close()
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
	packageHandler := PackageTransactionHandler(
		func(ctx context.Context, caller helperproto.Caller, request helperproto.Request) error {
			if caller != helperproto.CallerUI {
				return fmt.Errorf("package transaction caller is unauthorized")
			}
			return withPackageService(func(service *packages.Service) error { return service.ValidateRequest(ctx, request) })
		},
		func(ctx context.Context, caller helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
			if caller != helperproto.CallerUI || secret != nil {
				return ExecutionResult{}, fmt.Errorf("package transaction execution authority is invalid")
			}
			var digest string
			err := withPackageService(func(service *packages.Service) error {
				var executeErr error
				digest, executeErr = service.Execute(ctx, request)
				return executeErr
			})
			return ExecutionResult{ResultDigest: digest}, err
		},
	)
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
			return ExecutionResult{}, err
		}
		fingerprint, err = secrets.CurrentAdminTokenFingerprint()
		return ExecutionResult{ResultDigest: fingerprint}, err
	})
	profileHandler := ManagementProfileHandler(authRevalidate, func(_ context.Context, _ helperproto.Caller, _ helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
		if secret != nil {
			return ExecutionResult{}, fmt.Errorf("Management profile request carried secret")
		}
		return ExecutionResult{ResultDigest: profileDigest(managementProfile())}, nil
	})
	server, err := NewServer(config.Identities, []Registration{applicationHandler, packageHandler, verifyHandler, sourceHandler, rotateHandler, reconcileHandler, profileHandler}, Options{})
	if err != nil {
		return err
	}
	listener, err := ListenProtected(config.SocketGroup)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return server.Serve(ctx, listener)
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
	defer unix.Close(parentFD)
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
	defer file.Close()
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
