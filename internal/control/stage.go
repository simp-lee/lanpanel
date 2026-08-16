package control

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/certificates"
	"lanpanel/internal/preflight"
)

// CandidateHost is the closed local half of first deploy. Implementations must
// keep every network endpoint in the candidate's private boundary; Public STUN
// belongs to S17B's later exposure-locked activation.
type CandidateHost interface {
	ValidateFreshCandidate(context.Context, Rendered) error
	CommitFreshBoundary(context.Context, Rendered) error
	InitializeDatabase(context.Context, Rendered) (DatabaseEvidence, error)
	StagePrivateService(context.Context, Rendered, DatabaseEvidence) (ServiceEvidence, error)
	StopPrivateService(context.Context, Candidate) error
}

type StageRequest struct {
	InstallationID   string
	JobID            string
	PlanID           string
	IntentGeneration uint64
	Rendered         Rendered
	Preflight        preflight.ExpansionRequest
	PreflightResult  preflight.Result
}

type Execution struct {
	store    *Store
	host     CandidateHost
	journal  Journal
	rendered Rendered
}

// Prepare performs only local, exactly journaled work. It intentionally stops
// at certificate_pending; startup recovery may resume these local phases but
// must never call a remote issuer. The authenticated request performs issuance
// separately and supplies its verified terminal identity to StageCertificate.
func Prepare(ctx context.Context, store *Store, host CandidateHost, request StageRequest) (*Execution, error) {
	if store == nil || host == nil || VerifyRendered(request.Rendered) != nil {
		return nil, fmt.Errorf("Headscale candidate staging authority is incomplete")
	}
	if err := preflight.RequireExpansionResultForRequest(request.PreflightResult, request.Preflight, request.PreflightResult.ObservedAt); err != nil {
		return nil, err
	}
	if err := host.ValidateFreshCandidate(ctx, request.Rendered); err != nil {
		return nil, err
	}
	journal, err := NewJournal(request.InstallationID, request.JobID, request.PlanID, request.IntentGeneration, request.Rendered.Candidate, request.Preflight)
	if err != nil {
		return nil, err
	}
	if err := store.Create(ctx, journal); err != nil {
		return nil, err
	}
	if err := host.CommitFreshBoundary(ctx, request.Rendered); err != nil {
		return nil, errors.Join(err, host.StopPrivateService(context.WithoutCancel(ctx), request.Rendered.Candidate))
	}
	execution := &Execution{store: store, host: host, journal: journal, rendered: request.Rendered}
	if err := execution.advanceLocal(ctx); err != nil {
		stopErr := host.StopPrivateService(ctx, request.Rendered.Candidate)
		return nil, errors.Join(err, stopErr)
	}
	return execution, nil
}

// ResumeLocal accepts only an exact existing journal and repeats no remote
// acquisition. It is used by explicit same-job re-entry or startup contraction.
func ResumeLocal(ctx context.Context, store *Store, host CandidateHost, rendered Rendered) (*Execution, error) {
	if store == nil || host == nil || VerifyRendered(rendered) != nil {
		return nil, fmt.Errorf("Headscale local resume authority incomplete")
	}
	journal, err := store.Read()
	if err != nil || journal.CandidateDigest == "" || journal.Candidate != rendered.Candidate {
		return nil, fmt.Errorf("Headscale local resume authority changed")
	}
	execution := &Execution{store: store, host: host, journal: journal, rendered: rendered}
	if journal.Phase == PhaseCertificatePending || journal.Phase == PhaseCertificateStaged {
		return execution, nil
	}
	if err := execution.advanceLocal(ctx); err != nil {
		stopErr := host.StopPrivateService(ctx, rendered.Candidate)
		return nil, errors.Join(err, stopErr)
	}
	return execution, nil
}

func (execution *Execution) advanceLocal(ctx context.Context) error {
	for {
		switch execution.journal.Phase {
		case PhasePrepared:
			evidence, err := execution.host.InitializeDatabase(ctx, execution.rendered)
			if err != nil {
				return err
			}
			next := execution.journal
			next.Phase = PhaseDatabaseCommitted
			next.Database = &evidence
			if err := execution.store.Replace(ctx, execution.journal, next); err != nil {
				return err
			}
			execution.journal = next
		case PhaseDatabaseCommitted:
			evidence, err := execution.host.StagePrivateService(ctx, execution.rendered, *execution.journal.Database)
			if err != nil {
				return err
			}
			if evidence.PublicSTUNOpen {
				return fmt.Errorf("Headscale candidate exposed public STUN before activation")
			}
			next := execution.journal
			next.Phase = PhaseServiceStaged
			next.Service = &evidence
			if err := execution.store.Replace(ctx, execution.journal, next); err != nil {
				return err
			}
			execution.journal = next
		case PhaseServiceStaged:
			next := execution.journal
			next.Phase = PhaseCertificatePending
			if err := execution.store.Replace(ctx, execution.journal, next); err != nil {
				return err
			}
			execution.journal = next
		case PhaseCertificatePending, PhaseCertificateStaged:
			return nil
		default:
			return fmt.Errorf("Headscale local candidate phase is not resumable")
		}
	}
}

// ResumeStoppedLocal is the explicit same-job recovery path after startup has
// contracted an interrupted private service. It re-probes only journaled local
// state and never invokes a remote issuer or creates a new identity.
func ResumeStoppedLocal(ctx context.Context, store *Store, host CandidateHost, rendered Rendered) (*Execution, error) {
	execution, err := ResumeLocal(ctx, store, host, rendered)
	if err != nil {
		return nil, err
	}
	if execution.journal.Phase != PhaseCertificatePending || execution.journal.Database == nil {
		return nil, fmt.Errorf("Headscale stopped local recovery is not certificate-pending")
	}
	evidence, err := host.StagePrivateService(ctx, rendered, *execution.journal.Database)
	if err != nil || evidence.Identity != execution.journal.Candidate.ServiceIdentity || evidence.PublicSTUNOpen {
		return nil, errors.Join(err, fmt.Errorf("Headscale stopped local recovery probe mismatched"))
	}
	return execution, nil
}

func (execution *Execution) IssueRequest() (IssueRequest, error) {
	if execution == nil || execution.journal.Phase != PhaseCertificatePending {
		return IssueRequest{}, fmt.Errorf("Headscale certificate issuance is not pending")
	}
	return IssueRequest{JobID: execution.journal.JobID, PlanID: execution.journal.PlanID, IntentGeneration: execution.journal.IntentGeneration, CertificateID: execution.journal.Candidate.CertificateID, BindingDigest: execution.journal.Candidate.CertificateBinding, Domain: execution.journal.Candidate.ControlDomain}, nil
}

type IssueRequest struct {
	JobID            string `json:"job_id"`
	PlanID           string `json:"plan_id"`
	IntentGeneration uint64 `json:"intent_generation"`
	CertificateID    string `json:"certificate_id"`
	BindingDigest    string `json:"binding_digest"`
	Domain           string `json:"domain"`
}

// StageCertificate is the only remote-result handoff. It validates the exact
// same job/generation/binding and never activates the certificate pointer.
func (execution *Execution) StageCertificate(ctx context.Context, request IssueRequest, identity certificates.Identity) error {
	if execution == nil || execution.journal.Phase != PhaseCertificatePending {
		return fmt.Errorf("Headscale certificate result has no pending authority")
	}
	expected, err := execution.IssueRequest()
	if err != nil || request != expected || certificates.ValidateIdentity(identity) != nil || identity.ID != request.CertificateID || identity.BindingIdentity != request.BindingDigest || !equalDomains(identity.Domains, []string{request.Domain}) {
		return fmt.Errorf("Headscale certificate result differs from deploy authority")
	}
	next := execution.journal
	next.Phase = PhaseCertificateStaged
	next.Certificate = &identity
	if err := execution.store.Replace(ctx, execution.journal, next); err != nil {
		return err
	}
	execution.journal = next
	return nil
}

func (execution *Execution) Journal() Journal {
	if execution == nil {
		return Journal{}
	}
	return execution.journal
}
func equalDomains(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
