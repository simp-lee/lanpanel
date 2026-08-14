//go:build linux

package acme

import (
	"context"
	"fmt"
	"lanpanel/internal/child"
	"slices"
	"strings"
)

type IssueRequest struct {
	CertificateID    string
	Domains          []string
	Binding          Binding
	UID              uint32
	GID              uint32
	Chroot           string
	ExecutableDigest string
}
type IssueResult struct {
	StdoutDigest string
	StderrDigest string
}

type legoRunner interface {
	RunInvocation(context.Context, child.ProfileID, child.Invocation, []byte) (child.Result, error)
}

func RunLego(ctx context.Context, launcher legoRunner, request IssueRequest) (IssueResult, error) {
	if launcher == nil || request.CertificateID == "" || len(request.Domains) == 0 {
		return IssueResult{}, fmt.Errorf("lego issue authority incomplete")
	}
	if err := ValidateBinding(request.Binding); err != nil {
		return IssueResult{}, err
	}
	domains := append([]string(nil), request.Domains...)
	slices.Sort(domains)
	environment, err := BuildEnvironment(request.Binding)
	if err != nil {
		return IssueResult{}, err
	}
	for index, value := range environment {
		key, path, found := strings.Cut(value, "=")
		if found && strings.HasSuffix(key, "_FILE") {
			environment[index] = key + "=" + path
		}
	}
	frame, err := EncodeEnvironmentFrame(environment)
	if err != nil {
		return IssueResult{}, err
	}
	webroot := ""
	if request.Binding.Method == ChallengeHTTP01 {
		webroot = "/var/lib/lanpanel/certificates/webroot/" + request.CertificateID
	}
	invocation := child.Invocation{Lego: &child.LegoInvocation{CertificateID: request.CertificateID, DirectoryURL: request.Binding.DirectoryURL, AccountEmail: request.Binding.AccountEmail, Method: string(request.Binding.Method), Provider: string(request.Binding.Provider), Domains: domains, Webroot: webroot, DataPath: "/work", UID: request.UID, GID: request.GID, Chroot: request.Chroot, ExecutableDigest: request.ExecutableDigest, Environment: append([]string(nil), environment...)}}
	result, err := launcher.RunInvocation(ctx, child.ProfileLego, invocation, frame)
	observed := IssueResult{StdoutDigest: result.StdoutDigest, StderrDigest: result.StderrDigest}
	if err != nil || result.ExitCode != 0 || result.OutputCutOff {
		return observed, fmt.Errorf("lego child failed with redacted result: %w", err)
	}
	return observed, nil
}
