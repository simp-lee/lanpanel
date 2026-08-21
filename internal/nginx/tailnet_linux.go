//go:build linux

package nginx

import (
	"fmt"
	"lanpanel/internal/tailnet"
	"net"
	"net/netip"
)

func VerifyTailnetRoutes(manifest Manifest) error {
	for _, entry := range manifest.Entries {
		upstream, tailnetTarget := "", false
		if entry.Domain != nil && entry.Domain.Tailnet {
			upstream, tailnetTarget = entry.Domain.UpstreamAddress, true
		}
		if entry.Temporary != nil && entry.Temporary.Tailnet {
			upstream, tailnetTarget = entry.Temporary.UpstreamAddress, true
		}
		if !tailnetTarget {
			continue
		}
		host, _, err := net.SplitHostPort(upstream)
		if err != nil {
			return err
		}
		address, err := netip.ParseAddr(host)
		if err != nil {
			return err
		}
		source, sourceErr := netip.ParseAddr(func() string {
			if entry.Domain != nil {
				return entry.Domain.UpstreamSource
			}
			return entry.Temporary.UpstreamSource
		}())
		if sourceErr != nil {
			return sourceErr
		}
		device, err := tailnet.KernelInterfaceFor(source, address)
		if err != nil || device != "tailscale0" {
			return fmt.Errorf("active tailnet route for %s is not bound to tailscale0", entry.ResourceID)
		}
	}
	return nil
}
