//go:build linux

package ui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"lanpanel/internal/helperproto"
)

type FixedProfileProvider struct{}

func (FixedProfileProvider) Current(ctx context.Context) (Profile, error) {
	digest, err := helperRequest(ctx, helperproto.OperationManagementProfile, nil)
	if err != nil {
		return ProfileEmergency, err
	}
	if digest == profileDigest(ProfileNormal) {
		return ProfileNormal, nil
	}
	if digest == profileDigest(ProfileEmergency) {
		return ProfileEmergency, nil
	}
	return ProfileEmergency, fmt.Errorf("helper returned unknown Management profile")
}
func profileDigest(profile Profile) string {
	digest := sha256.Sum256([]byte("lanpanel.management.profile/" + string(profile)))
	return "sha256:" + hex.EncodeToString(digest[:])
}
