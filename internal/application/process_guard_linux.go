//go:build linux

package application

import (
	"fmt"
	"lanpanel/internal/domain"
)

func RunningProcessBundles() ([]domain.ProcessBundle, error) {
	service, err := OpenFixed()
	if err != nil {
		return nil, err
	}
	defer service.Close()
	document, err := service.normal.Read()
	if err != nil {
		return nil, err
	}
	raw, present := document.Entries["installations/current"]
	if !present {
		return nil, fmt.Errorf("installation authority missing")
	}
	installation, err := domain.DecodeInstallation(raw)
	if err != nil {
		return nil, err
	}
	result := []domain.ProcessBundle{}
	for _, resource := range installation.Resources {
		if resource.ManagedProcess == nil || resource.ManagedProcess.Requested != domain.ProcessRequestedRunning {
			continue
		}
		if resource.ManagedProcess.Applied == nil {
			return nil, fmt.Errorf("requested running process omits applied bundle")
		}
		result = append(result, *resource.ManagedProcess.Applied)
	}
	return result, nil
}
