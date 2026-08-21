// Package secrets owns bounded plaintext only for its immediate intended consumer.
package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

type Value struct {
	mu    sync.Mutex
	value []byte
}

func New(value []byte) (*Value, error) {
	if len(value) == 0 || len(value) > 8<<10 {
		return nil, fmt.Errorf("secret value is empty or unbounded")
	}
	return &Value{value: append([]byte(nil), value...)}, nil
}

func (value *Value) Use(consumer func([]byte) error) error {
	if value == nil || consumer == nil {
		return fmt.Errorf("secret value is unavailable")
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	if len(value.value) == 0 {
		return fmt.Errorf("secret value was already consumed")
	}
	defer value.destroyLocked()
	return consumer(value.value)
}

func (value *Value) Fingerprint() (string, error) {
	if value == nil {
		return "", fmt.Errorf("secret value is unavailable")
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	if len(value.value) == 0 {
		return "", fmt.Errorf("secret value was already consumed")
	}
	digest := sha256.Sum256(value.value)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (value *Value) Destroy() {
	if value == nil {
		return
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	value.destroyLocked()
}
func (value *Value) destroyLocked() { clear(value.value); value.value = nil }
