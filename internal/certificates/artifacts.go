package certificates

import (
	"cmp"
	"fmt"
	"slices"
)

// Artifact is resource-lifetime ownership, not a claim that its files still
// exist. Failed staging attempts remain authorized until resource deletion.
// A retried generation can have multiple exact, previously authorized bytes.
type Artifact struct {
	CertificateID string         `json:"certificate_id"`
	Generation    uint64         `json:"generation"`
	Bundle        BundleIdentity `json:"bundle"`
}

func CompareArtifacts(a, b Artifact) int {
	if value := cmp.Compare(a.CertificateID, b.CertificateID); value != 0 {
		return value
	}
	if value := cmp.Compare(a.Generation, b.Generation); value != 0 {
		return value
	}
	left := []string{a.Bundle.Fingerprint, a.Bundle.SANIdentity, a.Bundle.ChainIdentity, a.Bundle.IssuerIdentity, a.Bundle.BindingIdentity, a.Bundle.DirectoryIdentity}
	right := []string{b.Bundle.Fingerprint, b.Bundle.SANIdentity, b.Bundle.ChainIdentity, b.Bundle.IssuerIdentity, b.Bundle.BindingIdentity, b.Bundle.DirectoryIdentity}
	return slices.Compare(left, right)
}

func ValidateArtifacts(artifacts []Artifact) error {
	for index, artifact := range artifacts {
		if !certificateID(artifact.CertificateID) || artifact.Generation == 0 || ValidateBundleIdentity(artifact.Bundle) != nil {
			return fmt.Errorf("certificate inventory identity invalid")
		}
		if index > 0 && CompareArtifacts(artifacts[index-1], artifact) >= 0 {
			return fmt.Errorf("certificate inventory must be sorted and unique")
		}
	}
	return nil
}

func AddArtifact(artifacts []Artifact, artifact Artifact) []Artifact {
	result := append(append([]Artifact(nil), artifacts...), artifact)
	slices.SortFunc(result, CompareArtifacts)
	return slices.Compact(result)
}
