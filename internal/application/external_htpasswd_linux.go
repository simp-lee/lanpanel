//go:build linux

package application

import (
	"context"
	"encoding/json"
	"fmt"
	"lanpanel/internal/domain"
	"lanpanel/internal/htpasswdref"
	"lanpanel/internal/jobs"
	"lanpanel/internal/operations"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type ExternalHTPasswdResult struct {
	Job          jobs.Record
	CredentialID string
	Fingerprint  string
}

func pathContainedBy(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, candidate)
	return err == nil && !filepath.IsAbs(relative) && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func RegisterExternalHTPasswd(ctx context.Context, resourceID, path, actor string) (ExternalHTPasswdResult, error) {
	if err := requireNoDegradedAppliedSource(resourceID); err != nil {
		return ExternalHTPasswdResult{}, err
	}
	gid, err := nginxGroupGID()
	if err != nil {
		return ExternalHTPasswdResult{}, err
	}
	identity, err := htpasswdref.Validate(path, gid)
	if err != nil {
		return ExternalHTPasswdResult{}, err
	}
	service, err := OpenFixed()
	if err != nil {
		return ExternalHTPasswdResult{}, err
	}
	installation, err := loadBasicInstallation(service)
	_ = service.Close()
	if err != nil {
		return ExternalHTPasswdResult{}, err
	}
	resourcePresent := false
	for _, resource := range installation.Resources {
		if resource.ID == resourceID {
			resourcePresent = true
		}
	}
	if !resourcePresent {
		return ExternalHTPasswdResult{}, fmt.Errorf("external htpasswd owner resource missing")
	}
	for _, candidate := range protectedStaticPaths(installation) {
		if pathContainedBy(candidate, path) {
			return ExternalHTPasswdResult{}, fmt.Errorf("external htpasswd overlaps protected managed path")
		}
	}
	credentialID, err := newCredentialID()
	if err != nil {
		return ExternalHTPasswdResult{}, err
	}
	credential := domain.Credential{ID: credentialID, Kind: "external_htpasswd", OwnerResourceID: resourceID, ExternalPath: path, Fingerprint: identity.Fingerprint}
	encoded, _ := json.Marshal(credential)
	execution, err := beginBasic(ctx, operations.ExternalHTPasswdRegister, "resource/"+resourceID, actor, operations.SafetyBinding{ResourceID: resourceID, CandidateDigest: identity.Fingerprint, CandidateBundle: shaDigest(encoded), Deadline: time.Now().UTC().Add(time.Minute)})
	if err != nil {
		return ExternalHTPasswdResult{}, err
	}
	defer execution.Close()
	freshInstallation, err := loadBasicInstallation(execution.service)
	if err != nil {
		return ExternalHTPasswdResult{}, err
	}
	for _, candidate := range protectedStaticPaths(freshInstallation) {
		if pathContainedBy(candidate, path) {
			return ExternalHTPasswdResult{}, fmt.Errorf("external htpasswd overlaps protected managed path")
		}
	}
	lockedIdentity, err := htpasswdref.Validate(path, gid)
	if err != nil || !reflect.DeepEqual(lockedIdentity, identity) {
		return ExternalHTPasswdResult{}, fmt.Errorf("external htpasswd changed before commit")
	}
	if err := execution.admitter.CommitExternalHTPasswd(ctx, execution.mutation, execution.exposure, execution.intent.IntentGeneration, execution.job.ID, resourceID, credential); err != nil {
		return ExternalHTPasswdResult{}, err
	}
	record, err := execution.admitter.Complete(ctx, execution.mutation, execution.exposure, execution.intent.IntentGeneration+1, execution.job.ID, "complete", nil, []jobs.Postcondition{{Kind: "external_htpasswd_registered", Status: jobs.PostconditionVerified, Identity: identity.Fingerprint}}, "")
	return ExternalHTPasswdResult{Job: record, CredentialID: credentialID, Fingerprint: identity.Fingerprint}, err
}
