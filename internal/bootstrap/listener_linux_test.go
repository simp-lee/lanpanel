//go:build linux

package bootstrap

import (
	"lanpanel/internal/identity"
	"os"
	"strconv"
	"testing"
)

func TestInheritedManagementListenerRejectsGenerationAndDescriptorMismatch(t *testing.T) {
	generation := "gen_00000000000000000000000000000001"
	authority := identity.ManagementAuthority{Address: "127.1.2.3", Port: 52345}
	environment := map[string]string{"LANPANEL_SOCKET_GENERATION": generation, "LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "1", "LISTEN_FDNAMES": ManagementFDNamePrefix + "gen_00000000000000000000000000000002"}
	for key, value := range environment {
		t.Setenv(key, value)
	}
	if listener, err := InheritedManagementListener(authority, generation); err == nil {
		_ = listener.Close()
		t.Fatal("socket/service generation mismatch was accepted")
	}
}
