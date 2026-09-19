//go:build linux

package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	managedconnector "lanpanel/internal/connector"
	"lanpanel/internal/domain"
	"lanpanel/internal/identity"
	"lanpanel/internal/jobs"
	"lanpanel/internal/locks"
	"lanpanel/internal/operations"
	"lanpanel/internal/plans"
	"lanpanel/internal/tailnet"
	"net/url"
	"strings"
	"time"
)

type ConnectorBindingPayload struct {
	ControlURL string `json:"control_url"`
}
type ConnectorLoginPayload struct {
	PlanID       string `json:"plan_id,omitempty"`
	Confirmation string `json:"confirmation,omitempty"`
}
type ConnectorMutationResult struct {
	JobID string `json:"job_id"`
}
type ConnectorVerifyResult struct {
	Observation managedconnector.Observation `json:"observation"`
}
type ConnectorLoginExecutor func(context.Context, string, string) error

func SetConnectorBinding(ctx context.Context, actor Actor, payload ConnectorBindingPayload) (result ConnectorMutationResult, resultErr error) {
	if !canonicalConnectorControlURL(payload.ControlURL) {
		return ConnectorMutationResult{}, fmt.Errorf("connector ControlURL is invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	if installation.Connector != nil {
		return ConnectorMutationResult{}, fmt.Errorf("connector binding is set-once")
	}
	for _, resource := range installation.Resources {
		if resource.Target.Kind == domain.AppTargetTailnetHTTP {
			return ConnectorMutationResult{}, fmt.Errorf("tailnet resource exists before connector binding")
		}
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return ConnectorMutationResult{}, err
	}
	connectorID := "con_" + hex.EncodeToString(idBytes)
	clear(idBytes)
	connector := domain.TailnetConnector{ID: connectorID, ControlURL: payload.ControlURL, ManagedPaths: domain.ConnectorManagedPaths()}
	configDigest := digestLifecycle(connector)
	actorID, err := actorAuthority(actor)
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	admitter, err := service.resourceAdmitter()
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.ConnectorBindingSet, Target: "connector", ActorIdentity: actorID, Source: operations.AdmissionUI, SafetyBinding: operations.SafetyBinding{CandidateDigest: configDigest, CandidateBundle: configDigest}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if admitErr != nil || releaseErr != nil {
		if job.ID != "" {
			return ConnectorMutationResult{JobID: job.ID}, MutationJobError{JobID: job.ID, Err: errors.Join(admitErr, releaseErr)}
		}
		return ConnectorMutationResult{}, errors.Join(admitErr, releaseErr)
	}
	defer func() {
		if resultErr != nil {
			result.JobID = job.ID
			resultErr = MutationJobError{JobID: job.ID, Err: resultErr}
		}
	}()
	set, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return ConnectorMutationResult{}, rejectReservedConnectorMutation(ctx, service, admitter, job.ID, err)
	}
	mutation, exposure, err := set.AcquireExposure(ctx, "connector", service.manager)
	if err != nil {
		_ = set.Close()
		return ConnectorMutationResult{}, rejectReservedConnectorMutation(ctx, service, admitter, job.ID, err)
	}
	fresh, err := service.normal.Read()
	if err != nil {
		cleanupErr := errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close())
		return ConnectorMutationResult{}, rejectReservedConnectorMutation(ctx, service, admitter, job.ID, errors.Join(err, cleanupErr))
	}
	if _, err := admitter.BeginUI(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1}); err != nil {
		cleanupErr := errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close())
		return ConnectorMutationResult{}, rejectReservedConnectorMutation(ctx, service, admitter, job.ID, errors.Join(err, cleanupErr))
	}
	defer func(ignore func() error) { _ = ignore() }(set.Close)
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	connector.LastOperation, connector.LastJobID = domain.OperationConnectorBindingSet, job.ID
	fresh, _ = service.normal.Read()
	if err := admitter.CommitConnectorBinding(ctx, mutation, exposure, fresh.Revision, job.ID, connector); err != nil {
		return ConnectorMutationResult{}, err
	}
	fresh, _ = service.normal.Read()
	if _, err := admitter.Complete(ctx, mutation, exposure, fresh.Revision, job.ID, "complete", nil, []jobs.Postcondition{{Kind: "connector_binding_committed", Status: jobs.PostconditionVerified, Identity: connectorID}}, ""); err != nil {
		return ConnectorMutationResult{}, err
	}
	return ConnectorMutationResult{JobID: job.ID}, nil
}

func VerifyConnector(ctx context.Context, runner managedconnector.Runner, route managedconnector.RouteObserver) (ConnectorVerifyResult, error) {
	service, err := OpenFixed()
	if err != nil {
		return ConnectorVerifyResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return ConnectorVerifyResult{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil || installation.Connector == nil {
		return ConnectorVerifyResult{}, errors.Join(err, domain.PrerequisiteError{Code: domain.PrerequisiteConnectorRequired})
	}
	installed, err := readCommittedReleaseIdentity()
	if err != nil {
		return ConnectorVerifyResult{}, err
	}
	if runner == nil {
		account, err := tailscaleAccount(installation.InstallationID)
		if err != nil {
			return ConnectorVerifyResult{}, err
		}
		runner, err = managedconnector.NewFixedRunner(account.UID, account.GID, installed.Tailscale.Digest)
		if err != nil {
			return ConnectorVerifyResult{}, err
		}
	}
	if route == nil {
		observer := tailnet.KernelRouteObserver{}
		route = observer
	}
	observation, err := managedconnector.Verify(ctx, runner, route, installed.TailscaleVersion, installation.Connector.ControlURL, time.Now().UTC())
	return ConnectorVerifyResult{Observation: observation}, err
}

func CreateConnectorLoginPlan(ctx context.Context, actor Actor) (plans.Plan, error) {
	service, err := OpenFixed()
	if err != nil {
		return plans.Plan{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return plans.Plan{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil || installation.Connector == nil {
		return plans.Plan{}, errors.Join(err, domain.PrerequisiteError{Code: domain.PrerequisiteConnectorRequired})
	}
	actorID, err := actorAuthority(actor)
	if err != nil {
		return plans.Plan{}, err
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return plans.Plan{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(admission.Release)
	digest := digestLifecycle(installation.Connector)
	return service.plans.Create(ctx, admission, document.Revision, plans.Spec{Operation: string(domain.OperationConnectorLogin), Target: plans.Target{Kind: plans.TargetConnector}, ActorIdentity: actorID, Config: plans.DigestBinding{Applicable: true, Digest: digest}, ExposureSummary: "assisted login to fixed ControlURL " + installation.Connector.ControlURL, Prerequisites: "one-time auth key is consumed from this request and never persisted", Lifetime: 10 * time.Minute})
}

func ExecuteConnectorLogin(ctx context.Context, actor Actor, payload ConnectorLoginPayload, login ConnectorLoginExecutor, runner managedconnector.Runner, route managedconnector.RouteObserver) (result ConnectorMutationResult, resultErr error) {
	if payload.PlanID == "" || payload.Confirmation != "login" || login == nil {
		return ConnectorMutationResult{}, fmt.Errorf("connector login confirmation is invalid")
	}
	service, err := OpenFixed()
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil || installation.Connector == nil {
		return ConnectorMutationResult{}, errors.Join(err, domain.PrerequisiteError{Code: domain.PrerequisiteConnectorRequired})
	}
	actorID, err := actorAuthority(actor)
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	plan, err := service.ReadPlan(payload.PlanID)
	digest := digestLifecycle(installation.Connector)
	if err != nil || plan.Operation != string(domain.OperationConnectorLogin) || plan.Target.Kind != plans.TargetConnector || plan.ActorIdentity != actorID || plan.Config.Digest != digest {
		return ConnectorMutationResult{}, fmt.Errorf("connector login Plan authority changed")
	}
	admitter, err := service.Admitter(plan)
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	admission, err := service.manager.Acquire(ctx, locks.MutationAdmission)
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	job, admitErr := admitter.Admit(ctx, admission, operations.AdmitRequest{Operation: operations.ConnectorLogin, Target: "connector", ActorIdentity: actorID, PlanID: plan.ID, Source: operations.AdmissionPlan, SafetyBinding: operations.SafetyBinding{CandidateDigest: digest, CandidateBundle: digest, PlanID: plan.ID}, ExpectedRevision: document.Revision})
	releaseErr := admission.Release()
	if admitErr != nil || releaseErr != nil {
		if job.ID != "" {
			return ConnectorMutationResult{JobID: job.ID}, MutationJobError{JobID: job.ID, Err: errors.Join(admitErr, releaseErr)}
		}
		return ConnectorMutationResult{}, errors.Join(admitErr, releaseErr)
	}
	defer func() {
		if resultErr != nil {
			result.JobID = job.ID
			resultErr = MutationJobError{JobID: job.ID, Err: resultErr}
		}
	}()
	set, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
	if err != nil {
		return ConnectorMutationResult{}, rejectReservedConnectorMutation(ctx, service, admitter, job.ID, err)
	}
	mutation, exposure, err := set.AcquireExposure(ctx, "connector", service.manager)
	if err != nil {
		_ = set.Close()
		return ConnectorMutationResult{}, rejectReservedConnectorMutation(ctx, service, admitter, job.ID, err)
	}
	fresh, err := service.normal.Read()
	if err != nil {
		cleanupErr := errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close())
		return ConnectorMutationResult{}, rejectReservedConnectorMutation(ctx, service, admitter, job.ID, errors.Join(err, cleanupErr))
	}
	intent, err := admitter.ConsumePlan(ctx, mutation, exposure, operations.ConsumeRequest{JobID: job.ID, ExpectedRevision: fresh.Revision, IntentGeneration: fresh.Revision + 1, ConfirmationProof: plan.NonceDigest})
	if err != nil {
		cleanupErr := errors.Join(operations.ReleaseExposure(mutation, exposure), set.Close())
		return ConnectorMutationResult{}, rejectReservedConnectorMutation(ctx, service, admitter, job.ID, errors.Join(err, cleanupErr))
	}
	defer func(ignore func() error) { _ = ignore() }(set.Close)
	defer func() { _ = operations.ReleaseExposure(mutation, exposure) }()
	terminalNoEffect := func(cause error) error {
		return completeConnectorLoginNotStarted(ctx, service, admitter, mutation, exposure, job.ID, cause)
	}
	installed, err := readCommittedReleaseIdentity()
	if err != nil {
		return ConnectorMutationResult{}, terminalNoEffect(err)
	}
	if runner == nil {
		account, accountErr := tailscaleAccount(installation.InstallationID)
		if accountErr != nil {
			return ConnectorMutationResult{}, terminalNoEffect(accountErr)
		}
		runner, err = managedconnector.NewFixedRunner(account.UID, account.GID, installed.Tailscale.Digest)
		if err != nil {
			return ConnectorMutationResult{}, terminalNoEffect(err)
		}
	}
	if err := managedconnector.PreflightLogin(ctx, runner, installation.Connector.ControlURL); err != nil {
		return ConnectorMutationResult{}, terminalNoEffect(err)
	}
	_, err = admitter.EnterRemoteWait(ctx, mutation, exposure, intent.IntentGeneration, job.ID)
	mutation, exposure = nil, nil
	if err != nil {
		return ConnectorMutationResult{}, err
	}
	reenter := func() (uint64, error) {
		current, readErr := service.normal.Read()
		if readErr != nil {
			return 0, readErr
		}
		reentered, nextMutation, nextExposure, reenterErr := admitter.Reenter(context.WithoutCancel(ctx), set, service.manager, current.Revision, job.ID)
		if reenterErr != nil {
			return 0, reenterErr
		}
		mutation, exposure = nextMutation, nextExposure
		return reentered.IntentGeneration, nil
	}
	terminalUnknown := func(cause error, code string) error {
		revision, reenterErr := reenter()
		if reenterErr != nil {
			return errors.Join(cause, reenterErr)
		}
		_, completeErr := admitter.Complete(context.WithoutCancel(ctx), mutation, exposure, revision, job.ID, "source_unknown", nil, []jobs.Postcondition{{Kind: "connector_login_observation", Status: jobs.PostconditionUnobserved, Identity: job.ID}}, code)
		return errors.Join(cause, completeErr)
	}
	if err := login(ctx, job.ID, installation.Connector.ControlURL); err != nil {
		return ConnectorMutationResult{}, terminalUnknown(err, "connector_login_failed")
	}
	if route == nil {
		observer := tailnet.KernelRouteObserver{}
		route = observer
	}
	if _, err := managedconnector.Verify(ctx, runner, route, installed.TailscaleVersion, installation.Connector.ControlURL, time.Now().UTC()); err != nil {
		return ConnectorMutationResult{}, terminalUnknown(err, "connector_login_unknown")
	}
	revision, reenterErr := reenter()
	if reenterErr != nil {
		return ConnectorMutationResult{}, reenterErr
	}
	if err := admitter.CommitConnectorLogin(ctx, mutation, exposure, revision, job.ID); err != nil {
		return ConnectorMutationResult{}, err
	}
	fresh, _ = service.normal.Read()
	if _, err := admitter.Complete(ctx, mutation, exposure, fresh.Revision, job.ID, "complete", nil, []jobs.Postcondition{{Kind: "connector_login_verified", Status: jobs.PostconditionVerified, Identity: installation.Connector.ID}}, ""); err != nil {
		return ConnectorMutationResult{}, err
	}
	return ConnectorMutationResult{JobID: job.ID}, nil
}

func completeConnectorLoginNotStarted(ctx context.Context, service *FixedService, admitter *operations.Admitter, mutation *operations.MutationLease, exposure *locks.Lease, jobID string, cause error) error {
	current, err := service.normal.Read()
	if err != nil {
		return errors.Join(cause, err)
	}
	_, err = admitter.Complete(context.WithoutCancel(ctx), mutation, exposure, current.Revision, jobID, "no_effect", nil, []jobs.Postcondition{{Kind: "connector_login_not_started", Status: jobs.PostconditionVerified, Identity: jobID}}, "connector_login_failed")
	return errors.Join(cause, err)
}

func ConnectorLoginTempAuthorities() (map[string]bool, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return nil, err
	}
	result := map[string]bool{}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var intent operations.Reservation
		if json.Unmarshal(raw, &intent) != nil {
			continue
		}
		if intent.Operation == operations.ConnectorLogin {
			result[intent.JobID] = true
		}
	}
	return result, nil
}

func OpenConnectorRuntime() (managedconnector.Runner, uint32, uint32, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, 0, 0, err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return nil, 0, 0, err
	}
	installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
	if err != nil {
		return nil, 0, 0, err
	}
	installed, err := readCommittedReleaseIdentity()
	if err != nil {
		return nil, 0, 0, err
	}
	account, err := tailscaleAccount(installation.InstallationID)
	if err != nil {
		return nil, 0, 0, err
	}
	runner, err := managedconnector.NewFixedRunner(account.UID, account.GID, installed.Tailscale.Digest)
	return runner, account.UID, account.GID, err
}

func tailscaleAccount(installationID string) (identity.AccountIdentity, error) {
	set, err := identity.InstallationAccounts(installationID)
	if err != nil {
		return identity.AccountIdentity{}, err
	}
	present, values, err := identity.InspectAccounts(set)
	if err != nil || !present {
		return identity.AccountIdentity{}, fmt.Errorf("tailscale operator account unavailable: %w", err)
	}
	value, ok := identity.IdentityFor(identity.AccountSet{Identities: values}, identity.RoleTailscale)
	if !ok {
		return identity.AccountIdentity{}, fmt.Errorf("tailscale operator identity missing")
	}
	return value, nil
}

func rejectReservedConnectorMutation(ctx context.Context, service *FixedService, admitter *operations.Admitter, jobID string, cause error) error {
	lease, acquireErr := service.manager.Acquire(context.WithoutCancel(ctx), locks.MutationAdmission)
	if acquireErr != nil {
		return errors.Join(cause, acquireErr)
	}
	defer func(ignore func() error) { _ = ignore() }(lease.Release)
	current, readErr := service.normal.Read()
	if readErr != nil {
		return errors.Join(cause, readErr)
	}
	return errors.Join(cause, admitter.RejectReservation(context.WithoutCancel(ctx), lease, current.Revision, jobID, "plan_consumption_rejected"))
}

func canonicalConnectorControlURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}
