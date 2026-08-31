//go:build linux

package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/operations"
	"strings"
)

type registrationRecoveryStage uint8

const (
	registrationRecoverySkip registrationRecoveryStage = iota
	registrationRecoveryReject
	registrationRecoveryLocal
	registrationRecoveryInvalid
)

func classifyRegistrationRecovery(intent operations.Reservation) registrationRecoveryStage {
	if intent.Operation != operations.StaticRootRegister && intent.Operation != operations.ExternalHTPasswdRegister {
		return registrationRecoverySkip
	}
	switch intent.Phase {
	case operations.PhaseReserved:
		return registrationRecoveryReject
	case operations.PhaseLocalIntent:
		return registrationRecoveryLocal
	case operations.PhaseRejected, operations.PhaseTerminal:
		return registrationRecoverySkip
	default:
		return registrationRecoveryInvalid
	}
}

func ReconcileStaticRootRegistrations(ctx context.Context) error {
	service, err := OpenFixed()
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(service.Close)
	document, err := service.normal.Read()
	if err != nil {
		return err
	}
	admitter, err := service.TimerAdmitter()
	if err != nil {
		return err
	}
	for key, raw := range document.Entries {
		if !strings.HasPrefix(key, "intents/") {
			continue
		}
		var intent operations.Reservation
		if json.Unmarshal(raw, &intent) != nil {
			continue
		}
		switch classifyRegistrationRecovery(intent) {
		case registrationRecoverySkip:
			continue
		case registrationRecoveryReject:
			code := "static_root_registration_interrupted"
			if intent.Operation == operations.ExternalHTPasswdRegister {
				code = "external_htpasswd_registration_interrupted"
			}
			if err := rejectReservedBasicOperation(ctx, service, admitter, intent.JobID, code); err != nil {
				return err
			}
			document, err = service.normal.Read()
			if err != nil {
				return err
			}
			continue
		case registrationRecoveryInvalid:
			return fmt.Errorf("registration recovery phase changed")
		}
		installation, err := domain.DecodeInstallation(document.Entries["installations/current"])
		if err != nil {
			return err
		}
		matchedPath := ""
		for index := range installation.StaticRoots {
			root := &installation.StaticRoots[index]
			rootRaw, _ := json.Marshal(root)
			sum := sha256.Sum256(rootRaw)
			if intent.Operation == operations.StaticRootRegister && root.Fingerprint == intent.SafetyBinding.CandidateDigest && "sha256:"+hex.EncodeToString(sum[:]) == intent.SafetyBinding.CandidateBundle {
				if matchedPath != "" {
					return fmt.Errorf("registration recovery identity ambiguous")
				}
				matchedPath = root.Path
			}
		}
		for index := range installation.Credentials {
			credential := &installation.Credentials[index]
			raw, _ := json.Marshal(credential)
			sum := sha256.Sum256(raw)
			if intent.Operation == operations.ExternalHTPasswdRegister && credential.Fingerprint == intent.SafetyBinding.CandidateDigest && "sha256:"+hex.EncodeToString(sum[:]) == intent.SafetyBinding.CandidateBundle {
				if matchedPath != "" {
					return fmt.Errorf("registration recovery identity ambiguous")
				}
				matchedPath = credential.ExternalPath
			}
		}
		mutationSet, err := operations.OpenMutationSet(operations.MutationConfig{RootPath: fixedRoot + "/locks", Owner: 0, Group: 0, Mode: 0o700, Authority: service.manager.Authority()})
		if err != nil {
			return err
		}
		mutation, exposure, err := mutationSet.AcquireExposure(ctx, intent.Target, service.manager)
		if err != nil {
			_ = mutationSet.Close()
			return err
		}
		fresh, err := service.normal.Read()
		if err == nil {
			kind := "static_root"
			code := "static_root_registration_interrupted"
			if intent.Operation == operations.ExternalHTPasswdRegister {
				kind = "external_htpasswd"
				code = "external_htpasswd_registration_interrupted"
			}
			condition := jobs.Postcondition{Kind: kind + "_not_committed", Status: jobs.PostconditionKnown, Identity: intent.SafetyBinding.CandidateDigest}
			paths := []string{}
			if matchedPath != "" {
				condition.Kind = kind + "_committed_before_interruption"
				if intent.Operation == operations.StaticRootRegister {
					paths = []string{matchedPath}
				}
			}
			_, err = admitter.Complete(ctx, mutation, exposure, fresh.Revision, intent.JobID, "executor_died", paths, []jobs.Postcondition{condition}, code)
		}
		releaseErr := operations.ReleaseExposure(mutation, exposure)
		closeErr := mutationSet.Close()
		if err != nil {
			return err
		}
		if releaseErr != nil || closeErr != nil {
			return fmt.Errorf("static root recovery lock release failed")
		}
		document, err = service.normal.Read()
		if err != nil {
			return err
		}
	}
	return nil
}
