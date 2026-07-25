package cli

import (
	stdcontext "context"
	"lanpanel/internal/appconfig"
	"lanpanel/internal/apphost"
	"lanpanel/internal/domain"
	"lanpanel/internal/exposure"
	"lanpanel/internal/preflight"
	"time"
)

func cliAppHostMutationExposurePlan(version string, configPath string, cfg appconfig.Config, operation domain.ExposurePlanOperation, permissions preflight.PermissionState, modifiedPaths []string) (domain.ExposurePlan, error) {
	return cliAppHostMutationExposurePlanWithObservations(version, configPath, cfg, operation, permissions, modifiedPaths, exposure.AppObservations{})
}

func cliAppHostMutationExposurePlanWithObservations(version string, configPath string, cfg appconfig.Config, operation domain.ExposurePlanOperation, permissions preflight.PermissionState, modifiedPaths []string, overrides exposure.AppObservations) (domain.ExposurePlan, error) {
	instanceID, err := cliExposureInstanceID()
	if err != nil {
		return domain.ExposurePlan{}, err
	}
	observations, err := apphost.AppExposureObservations(stdcontext.Background(), apphost.ExposureObservationOptions{
		ConfigPath:    configPath,
		Config:        cfg,
		Operation:     operation,
		Permissions:   permissions,
		Dependencies:  testApphostDependencies(),
	})
	if err != nil {
		return domain.ExposurePlan{}, err
	}
	observations = mergeTestExposureObservations(observations, overrides)
	return exposure.AppPlanWithObservations(instanceID, version, cfg, exposure.AppPlanOptions{
		ConfigPath:    configPath,
		Actor:         cliActor(),
		Operation:     operation,
		CreatedAt:     time.Now().UTC(),
		ModifiedPaths: append([]string(nil), modifiedPaths...),
		BeforeDigest:  "none",
	}, observations)
}

func mergeTestExposureObservations(base exposure.AppObservations, overrides exposure.AppObservations) exposure.AppObservations {
	if overrides.BrowserAuthRuntimeStatus != "" {
		base.BrowserAuthRuntimeStatus = overrides.BrowserAuthRuntimeStatus
	}
	if overrides.BrowserAuthMarkerStatus != "" {
		base.BrowserAuthMarkerStatus = overrides.BrowserAuthMarkerStatus
	}
	return base
}
