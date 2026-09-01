package main

import (
	"context"
	"errors"
	"lanpanel/internal/qualification"
	"lanpanel/internal/release"
	"os"
	"testing"
	"time"
)

func TestRunLiveSignalCancellationAllowsBoundedCleanup(t *testing.T) {
	started := make(chan struct{})
	cleaned := make(chan struct{})
	returned := make(chan error, 1)
	go func() {
		_, _, err := runLiveWithSignals("ignored", func(ctx context.Context, _ string) (qualification.Prepared, release.LiveCleanupReport, error) {
			close(started)
			<-ctx.Done()
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			select {
			case <-time.After(10 * time.Millisecond):
				close(cleaned)
			case <-cleanupCtx.Done():
				return qualification.Prepared{}, release.LiveCleanupReport{}, cleanupCtx.Err()
			}
			return qualification.Prepared{}, release.LiveCleanupReport{}, ctx.Err()
		})
		returned <- err
	}()
	<-started
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("signal cancellation did not allow bounded cleanup")
	}
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("live run did not receive signal cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("live run did not return after signal cleanup")
	}
}
