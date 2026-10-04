//go:build linux

package packages

import (
	"bytes"
	"lanpanel/internal/child"
	"testing"
)

func TestStructuredProgressWriterReportsBoundedAPTEvents(t *testing.T) {
	var output bytes.Buffer
	var events []ProgressEvent
	writer := wrapProgressWriter(&output, func(event ProgressEvent) { events = append(events, event) }, child.ProfileAPTTransaction, 2)
	if _, err := writer.Write([]byte("Reading package lists... 0%\nUnpacking nginx\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("Setting up nginx\nignored diagnostic\n")); err != nil {
		t.Fatal(err)
	}
	if output.String() == "" || len(events) != 3 {
		t.Fatalf("output=%q events=%#v", output.String(), events)
	}
	if events[0].Stage != "apt_dpkg_transaction" || events[0].Current != 0 || events[0].Total != 2 || events[1].Current != 1 || events[2].Current != 1 {
		t.Fatalf("events=%#v", events)
	}
}
