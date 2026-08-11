package hostworkflow

import (
	"context"
	"lanpanel/internal/domain"
	"testing"
)

func TestServiceAppDeployReturnsCanceledResultBeforeHostWorkflow(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := Service{}.RunAppDeploy(ctx, "/tmp/lanpanel-app.yaml", domain.ExposurePlan{}, []string{"origin-protection-manual"})
	if err == nil {
		t.Fatal("RunAppDeploy() error = nil, want context cancellation")
	}
	if result.Kind != domain.JobKindAppDeploy || result.Status != domain.JobStatusFailed {
		t.Fatalf("result = %#v, want canceled app deploy result", result)
	}
	if result.RetryCommand != "Management UI" {
		t.Fatalf("retry action = %q", result.RetryCommand)
	}
}
