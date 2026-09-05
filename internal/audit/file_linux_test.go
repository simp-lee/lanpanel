//go:build linux

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileSinkIsDurableAndBounded(t *testing.T) {
	auditDirectory := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(auditDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(auditDirectory, "events.json")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < MaximumRecords+1; index++ {
		err := sink.Append(Record{Operation: "login", Target: "installation", Actor: "actor", At: time.Unix(int64(index+1), 0).UTC(), Result: "succeeded", Paths: []string{}})
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != MaximumRecords || !records[0].At.Equal(time.Unix(2, 0).UTC()) {
		t.Fatalf("records=%d first=%v", len(records), records[0].At)
	}
	second, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Append(Record{Operation: "logout", Target: "installation", Actor: "actor", At: time.Unix(999, 0).UTC(), Result: "succeeded", Paths: []string{}}); err != nil {
		t.Fatal(err)
	}
}
