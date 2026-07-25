package hostworkflow

import (
	"context"
	"lanpanel/internal/domain"
	"strings"
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
	if !strings.Contains(result.RetryCommand, "sudo lanpanel app deploy --config /tmp/lanpanel-app.yaml") {
		t.Fatalf("retry command = %q, want app deploy retry command", result.RetryCommand)
	}
	if !strings.Contains(result.RetryCommand, "--confirmation origin-protection-manual") {
		t.Fatalf("retry command = %q, want confirmation token", result.RetryCommand)
	}
}
