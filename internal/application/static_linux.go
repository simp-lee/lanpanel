//go:build linux

package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/jobs"
	"lanpanel/internal/operations"
	staticcontent "lanpanel/internal/static"
	"time"
)

type StaticRootResult struct {
	Job  jobs.Record              `json:"job"`
	Root domain.StaticContentRoot `json:"root"`
}

func RegisterStaticRoot(ctx context.Context, resourceID, path, actor string) (result StaticRootResult, resultErr error) {
	if err := requireNoDegradedAppliedSource(resourceID); err != nil {
		return result, err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return result, err
	}
	id := "static_" + hex.EncodeToString(raw)
	service, err := OpenFixed()
	if err != nil {
		return result, err
	}
	installation, err := loadBasicInstallation(service)
	_ = service.Close()
	if err != nil {
		return result, err
	}
	identity, err := staticcontent.Register(id, path, protectedStaticPaths(installation))
	if err != nil {
		return result, err
	}
	root := domain.StaticContentRoot{ID: identity.ID, OwnerResourceID: resourceID, Path: identity.Path, Fingerprint: identity.Fingerprint, Device: identity.Device}
	rootRaw, _ := json.Marshal(root)
	execution, err := beginBasic(ctx, operations.StaticRootRegister, "resource/"+resourceID, actor, operations.SafetyBinding{ResourceID: resourceID, CandidateDigest: identity.Fingerprint, CandidateBundle: shaDigest(rootRaw), Deadline: time.Now().UTC().Add(time.Minute)})
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, execution.Close()) }()
	freshInstallation, err := loadBasicInstallation(execution.service)
	if err != nil {
		completed, terminalErr := execution.completeNoEffect(ctx, jobs.Postcondition{Kind: "static_root_not_registered", Status: jobs.PostconditionVerified, Identity: identity.Fingerprint}, "static_root_revalidation_failed", err)
		result.Job = completed
		return result, terminalErr
	}
	lockedIdentity, err := staticcontent.Register(id, path, protectedStaticPaths(freshInstallation))
	if err != nil || lockedIdentity != identity {
		completed, terminalErr := execution.completeNoEffect(ctx, jobs.Postcondition{Kind: "static_root_not_registered", Status: jobs.PostconditionVerified, Identity: identity.Fingerprint}, "static_root_revalidation_failed", errors.Join(fmt.Errorf("static root identity changed before commit"), err))
		result.Job = completed
		return result, terminalErr
	}
	if err := execution.admitter.CommitStaticRoot(ctx, execution.mutation, execution.exposure, execution.intent.IntentGeneration, execution.job.ID, resourceID, root); err != nil {
		return result, err
	}
	record, err := execution.admitter.Complete(ctx, execution.mutation, execution.exposure, execution.intent.IntentGeneration+1, execution.job.ID, "complete", nil, []jobs.Postcondition{{Kind: "static_root_registered", Status: jobs.PostconditionVerified, Identity: identity.Fingerprint}}, "")
	if err != nil {
		return result, err
	}
	return StaticRootResult{Job: record, Root: root}, nil
}
