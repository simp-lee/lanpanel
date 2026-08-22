//go:build linux

package qualification

import (
	"fmt"
	"lanpanel/internal/release"
)

type ProtectedAttestationStore struct{ Path string }

func (store ProtectedAttestationStore) Write(data []byte) error {
	if _, err := release.DecodeLiveExecutorAttestation(data); err != nil {
		return fmt.Errorf("refuse invalid live executor attestation: %w", err)
	}
	if err := WriteSummary(store.Path, data); err != nil {
		return err
	}
	return sealProtectedFile(store.Path)
}
