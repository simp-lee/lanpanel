// Package roles dispatches the release-fixed same-binary process roles.
package roles

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

type Name string

const (
	UI                    Name = "ui"
	ChildExecutor         Name = "child-executor"
	Helper                Name = "helper"
	StartupGuard          Name = "startup-guard"
	ReloadGuard           Name = "reload-guard"
	RuntimeGuard          Name = "runtime-guard"
	ProcessGuard          Name = "process-guard"
	Installer             Name = "installer"
	StartupRecovery       Name = "startup-recovery"
	Timer                 Name = "timer"
	Relay                 Name = "relay"
	GoAccessRelay         Name = "goaccess-relay"
	GoAccessRetention     Name = "goaccess-retention"
	GoAccessAccountGuard  Name = "goaccess-account-guard"
	HeadscalePrivateProbe Name = "headscale-private-probe"
	HeadscaleControlRelay Name = "headscale-control-relay"
	HeadscaleSTUNRelay    Name = "headscale-stun-relay"
	PackageNoAutostart    Name = "package-no-autostart"
	ManagedExecutor       Name = "managed-executor"
)

var fixed = map[Name]struct{}{
	UI: {}, ChildExecutor: {}, Helper: {}, StartupGuard: {}, ReloadGuard: {}, RuntimeGuard: {}, Installer: {},
	StartupRecovery: {}, Timer: {}, Relay: {}, GoAccessRelay: {}, GoAccessRetention: {}, GoAccessAccountGuard: {}, HeadscalePrivateProbe: {}, HeadscaleControlRelay: {}, HeadscaleSTUNRelay: {}, PackageNoAutostart: {}, ManagedExecutor: {}, ProcessGuard: {},
}

type Handler func(args []string, stdout, stderr io.Writer) error

type Registration struct {
	Name    Name
	Handler Handler
}

type Registry struct{ handlers map[Name]Handler }

func NewRegistry(registrations []Registration) (*Registry, error) {
	registry := &Registry{handlers: make(map[Name]Handler, len(registrations))}
	for _, registration := range registrations {
		if _, ok := fixed[registration.Name]; !ok || registration.Handler == nil {
			return nil, fmt.Errorf("role registration is not release-fixed and complete")
		}
		if _, exists := registry.handlers[registration.Name]; exists {
			return nil, fmt.Errorf("role %q is registered twice", registration.Name)
		}
		registry.handlers[registration.Name] = registration.Handler
	}
	return registry, nil
}

func FixedNames() []Name {
	names := make([]Name, 0, len(fixed))
	for name := range fixed {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (registry *Registry) Names() []Name {
	if registry == nil {
		return nil
	}
	names := make([]Name, 0, len(registry.handlers))
	for name := range registry.handlers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (registry *Registry) Dispatch(args []string, stdout, stderr io.Writer, version string) error {
	if registry == nil || stdout == nil || stderr == nil {
		return fmt.Errorf("role dispatcher is incomplete")
	}
	if len(args) == 0 || len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		_, err := io.WriteString(stdout, registry.Help())
		return err
	}
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		_, err := fmt.Fprintf(stdout, "lanpanel %s\n", version)
		return err
	}
	name := Name(args[0])
	handler, ok := registry.handlers[name]
	if !ok {
		return fmt.Errorf("unknown or unavailable role %q", args[0])
	}
	return handler(append([]string(nil), args[1:]...), stdout, stderr)
}

func (registry *Registry) Help() string {
	names := registry.Names()
	if len(names) == 0 {
		return "LanPanel same-binary role dispatcher.\n\nNo operational roles are available in this build.\n"
	}
	var text strings.Builder
	text.WriteString("LanPanel same-binary role dispatcher.\n\nAvailable roles:\n")
	for _, name := range names {
		fmt.Fprintf(&text, "  %s\n", name)
	}
	return text.String()
}
