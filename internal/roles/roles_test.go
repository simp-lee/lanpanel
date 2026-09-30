package roles

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestDispatcherExposesOnlyCompleteFixedRoles(t *testing.T) {
	t.Run("fixed_complete_handlers_only", func(t *testing.T) {
		called := false
		registry, err := NewRegistry([]Registration{{Name: UI, Handler: func(args []string, stdout, stderr io.Writer) error {
			called = len(args) == 1 && args[0] == "session"
			return nil
		}}})
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if err := registry.Dispatch([]string{"ui", "session"}, &stdout, &stderr, "test"); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("registered role handler was not called")
		}
		if err := registry.Dispatch([]string{"deploy"}, &stdout, &stderr, "test"); err == nil {
			t.Fatal("management command entered dispatcher")
		}
		if _, err := NewRegistry([]Registration{{Name: "generic", Handler: func([]string, io.Writer, io.Writer) error { return nil }}}); err == nil {
			t.Fatal("generic role registered")
		}
		if _, err := NewRegistry([]Registration{{Name: Helper}}); err == nil {
			t.Fatal("incomplete role registered")
		}
	})
}

func TestFixedRoleCensus(t *testing.T) {
	t.Run("release_fixed_roles", func(t *testing.T) {
		want := []Name{ChildExecutor, DelegationProbe, GoAccessAccountGuard, GoAccessRelay, GoAccessRetention, HeadscaleControlRelay, HeadscalePrivateProbe, HeadscaleSTUNRelay, Helper, Installer, ManagedExecutor, PackageNoAutostart, Relay, ReloadGuard, RuntimeGuard, StartupGuard, StartupRecovery, Timer, UI}
		if !slices.Equal(FixedNames(), want) {
			t.Fatalf("fixed roles=%v want %v", FixedNames(), want)
		}
	})
}

func TestEmptyReleaseRegistryHasNoManagementSurface(t *testing.T) {
	registry, err := NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := registry.Dispatch(nil, &stdout, &stderr, "test"); err != nil {
		t.Fatal(err)
	}
	help := stdout.String()
	for _, forbidden := range []string{"deploy", "status", "verify", "init", "app", "--config", "json", "yaml", "generic"} {
		if strings.Contains(strings.ToLower(help), forbidden) {
			t.Fatalf("help exposes %q: %s", forbidden, help)
		}
	}
}
