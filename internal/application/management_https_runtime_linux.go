//go:build linux

package application

import (
	"context"
	"fmt"
	"lanpanel/internal/acme"
	"lanpanel/internal/activation"
	"lanpanel/internal/certificates"
	"lanpanel/internal/challenge"
	"lanpanel/internal/closure"
	"lanpanel/internal/filetxn"
	"lanpanel/internal/nginx"
)

type managementHTTPSHost interface {
	RemoveChallenge(context.Context, challenge.Prepared, activation.ChallengeReloadAuthority) (activation.Result, error)
	StopAndVerify(context.Context) (closure.RuntimeSnapshot, error)
	ObserveRuntime(context.Context, nginx.Manifest) (closure.RuntimeSnapshot, error)
	StartCertificate(context.Context, activation.ReloadAuthority) (closure.RuntimeSnapshot, error)
	ReloadCertificate(context.Context, activation.ReloadAuthority) (closure.RuntimeSnapshot, error)
	VerifyServedCertificate(context.Context, string, string) error
	RestoreCertificate(context.Context, certificates.Pointer, string, string, string, activation.ReloadAuthority) error
	ContractManagement(context.Context, nginx.Entry, activation.ReloadAuthority, bool) (activation.Result, error)
}

type managementHTTPSRuntime struct {
	NewHost               func() (managementHTTPSHost, nginx.Paths, filetxn.Owner, error)
	RemoveActiveChallenge func(context.Context, *CertificateExecution, managementHTTPSHost) error
	Audit                 func(nginx.Paths, filetxn.Owner) (nginx.Manifest, error)
	InstallEntry          func(context.Context, nginx.Paths, filetxn.Owner, nginx.Entry) (nginx.Manifest, []string, error)
	ActivePointerPath     func(string) (string, error)
	BundlePath            func(string, uint64) (string, error)
	ObservePointer        func(string) (string, error)
	VerifyBundleIdentity  func(string, uint64, certificates.BundleIdentity) error
	ActivatePointer       func(context.Context, certificates.Pointer) (certificates.PointerResult, error)
	RemovePointer         func(context.Context, certificates.Pointer, string) error
	RemoveInactiveBundle  func(string, uint64, certificates.BundleIdentity, uint32, uint32) error
	VerifyWebrootEmpty    func(string, uint32, uint32) error
	RemoveStage           func(string, uint32, uint32) error
	RemoveWebroot         func(string, uint32, uint32) error
}

func defaultManagementHTTPSRuntime() *managementHTTPSRuntime {
	return &managementHTTPSRuntime{
		NewHost: func() (managementHTTPSHost, nginx.Paths, filetxn.Owner, error) {
			host, err := activation.NewFixedHost()
			if err != nil {
				return nil, nginx.Paths{}, filetxn.Owner{}, err
			}
			return host, host.Paths, host.Owner, nil
		},
		RemoveActiveChallenge: func(ctx context.Context, execution *CertificateExecution, host managementHTTPSHost) error {
			fixedHost, ok := host.(activation.Host)
			if !ok {
				return fmt.Errorf("management HTTPS activation host authority is not fixed")
			}
			return execution.removeActiveChallenge(ctx, fixedHost)
		},
		Audit: func(paths nginx.Paths, owner filetxn.Owner) (nginx.Manifest, error) { return nginx.Audit(paths, owner) },
		InstallEntry: func(ctx context.Context, paths nginx.Paths, owner filetxn.Owner, entry nginx.Entry) (nginx.Manifest, []string, error) {
			return nginx.InstallEntry(ctx, paths, owner, entry)
		},
		ActivePointerPath:    certificates.ActivePointerPath,
		BundlePath:           certificates.BundlePath,
		ObservePointer:       certificates.ObservePointer,
		VerifyBundleIdentity: certificates.VerifyBundleIdentity,
		ActivatePointer:      certificates.ActivatePointer,
		RemovePointer:        certificates.RemovePointer,
		RemoveInactiveBundle: certificates.RemoveInactiveBundle,
		VerifyWebrootEmpty:   acme.VerifyWebrootEmpty,
		RemoveStage:          acme.RemoveStage,
		RemoveWebroot:        acme.RemoveWebroot,
	}
}

func (service *FixedService) managementHTTPSRuntime() *managementHTTPSRuntime {
	if service != nil && service.management != nil {
		return service.management
	}
	return defaultManagementHTTPSRuntime()
}

func (service *FixedService) managementHTTPSRoot() string {
	if service != nil && service.root != "" {
		return service.root
	}
	return fixedRoot
}

func (service *FixedService) managementHTTPSOwner() filetxn.Owner {
	if service != nil {
		return service.owner
	}
	return filetxn.Owner{UID: 0, GID: 0}
}
