//go:build linux

package bootstrap

import (
	"context"
	"fmt"
	"io"
	"lanpanel/internal/application"
	"lanpanel/internal/domain"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/ui"
	"os"
	"time"
)

// RunPublicTokenReset rotates the administrator token through the typed helper.
// It never reads or replaces the token file directly.
func RunPublicTokenReset(args []string, stdout io.Writer) error {
	if len(args) != 0 || stdout == nil {
		return fmt.Errorf("token reset accepts no options")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("token reset requires root; use sudo")
	}
	if err := RequireCommitted(FixedPaths()); err != nil {
		return fmt.Errorf("LanPanel installation is not committed: %w", err)
	}
	service, err := application.HelperService(ui.HelperApplicationRequest)
	if err != nil {
		return err
	}
	actor := application.Actor{Kind: application.ActorUI, Identity: "cli", Generation: 1}
	target := domain.OperationTarget{Kind: domain.OperationTargetInstallation}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	planned, err := service.Invoke(ctx, actor, application.Call{
		Operation: domain.OperationPlan,
		Target:    target,
		Payload:   application.PlanPayload{Operation: domain.OperationAdminTokenRotate, Target: target},
	})
	if err != nil {
		return fmt.Errorf("plan administrator token rotation: %w", err)
	}
	plan, ok := planned.Payload.(helperproto.ActionResult)
	if !ok || plan.PlanID == "" || plan.Confirmation == "" {
		return fmt.Errorf("administrator token rotation Plan is invalid")
	}
	rotated, err := service.Invoke(ctx, actor, application.Call{
		Operation: domain.OperationAdminTokenRotate,
		Target:    target,
		Payload:   application.ConfirmationPayload{PlanID: plan.PlanID, Confirmation: "rotate"},
	})
	if err != nil {
		return fmt.Errorf("rotate administrator token: %w", err)
	}
	result, ok := rotated.Payload.(application.RotationResult)
	if !ok || result.JobID == "" || len(result.Token) == 0 {
		clear(result.Token)
		return fmt.Errorf("administrator token rotation result is invalid")
	}
	defer clear(result.Token)
	if _, err := fmt.Fprintf(stdout, "Administrator token rotated. Save this token now:\n%s\nJob: %s\n", result.Token, result.JobID); err != nil {
		return err
	}
	return nil
}
