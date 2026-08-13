//go:build linux

package process

import (
	"fmt"
	"lanpanel/internal/domain"
	"os"
)

func RunGuard(args []string, load func() ([]domain.ProcessBundle, error)) error {
	if len(args) != 0 || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("process guard requires fixed root service invocation")
	}
	if load == nil {
		return fmt.Errorf("process guard durable authority loader missing")
	}
	bundles, err := load()
	if err != nil {
		return err
	}
	return InitializeListenGuards(bundles)
}
