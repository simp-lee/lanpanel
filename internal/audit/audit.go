// Package audit provides the bounded runtime Management audit sink.
package audit

import (
	"fmt"
	"sync"
	"time"
)

const MaximumRecords = 256

type Record struct {
	Operation string    `json:"operation"`
	Target    string    `json:"target"`
	Actor     string    `json:"actor"`
	At        time.Time `json:"at"`
	Result    string    `json:"result"`
	ErrorCode string    `json:"error_code,omitempty"`
	Paths     []string  `json:"paths"`
}

type Sink interface{ Append(Record) error }

type MemorySink struct {
	mu      sync.Mutex
	records []Record
}

func NewMemorySink() *MemorySink { return &MemorySink{} }

func (sink *MemorySink) Append(record Record) error {
	if sink == nil || record.Operation == "" || record.Target == "" || record.Actor == "" || record.At.IsZero() || record.Result == "" || len(record.Paths) > 8192 {
		return fmt.Errorf("audit record is invalid")
	}
	record.Paths = append([]string(nil), record.Paths...)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.records = append(sink.records, record)
	if len(sink.records) > MaximumRecords {
		sink.records = append([]Record(nil), sink.records[len(sink.records)-MaximumRecords:]...)
	}
	return nil
}

func (sink *MemorySink) Records() []Record {
	if sink == nil {
		return nil
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	result := make([]Record, len(sink.records))
	copy(result, sink.records)
	for index := range result {
		result[index].Paths = append([]string(nil), result[index].Paths...)
	}
	return result
}
