//go:build linux

package tailnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

type KernelRouteObserver struct{}

func (KernelRouteObserver) InterfaceFor(source, address netip.Addr) (string, error) {
	return KernelInterfaceFor(source, address)
}

func KernelInterfaceFor(source, address netip.Addr) (string, error) {
	if !source.IsValid() || source.IsLoopback() || source.IsUnspecified() || !address.IsValid() || address.IsLoopback() || address.IsUnspecified() || source.BitLen() != address.BitLen() {
		return "", fmt.Errorf("route source or target IP is invalid")
	}
	family := uint8(unix.AF_INET)
	sourceBytes, destinationBytes := source.AsSlice(), address.AsSlice()
	if address.Is6() {
		family = unix.AF_INET6
	}
	message := unix.RtMsg{Family: family, Dst_len: uint8(address.BitLen()), Src_len: uint8(source.BitLen())}
	var payload bytes.Buffer
	if err := binary.Write(&payload, binary.NativeEndian, message); err != nil {
		return "", err
	}
	writeRouteAttribute(&payload, unix.RTA_DST, destinationBytes)
	writeRouteAttribute(&payload, unix.RTA_SRC, sourceBytes)
	header := unix.NlMsghdr{Len: uint32(unix.NLMSG_HDRLEN + payload.Len()), Type: unix.RTM_GETROUTE, Flags: unix.NLM_F_REQUEST, Seq: 1}
	var packet bytes.Buffer
	if err := binary.Write(&packet, binary.NativeEndian, header); err != nil {
		return "", err
	}
	packet.Write(payload.Bytes())
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return "", err
	}
	if err := unix.Sendto(fd, packet.Bytes(), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return "", err
	}
	buffer := make([]byte, 64<<10)
	count, _, err := unix.Recvfrom(fd, buffer, 0)
	if err != nil {
		return "", err
	}
	messages, err := syscall.ParseNetlinkMessage(buffer[:count])
	if err != nil {
		return "", err
	}
	oif := 0
	for _, reply := range messages {
		if reply.Header.Seq != 1 {
			continue
		}
		if reply.Header.Type == unix.NLMSG_ERROR {
			return "", fmt.Errorf("kernel route lookup failed")
		}
		if reply.Header.Type != unix.RTM_NEWROUTE {
			continue
		}
		attributes, attrErr := syscall.ParseNetlinkRouteAttr(&reply)
		if attrErr != nil {
			return "", attrErr
		}
		for _, attribute := range attributes {
			if attribute.Attr.Type == unix.RTA_MULTIPATH {
				return "", fmt.Errorf("kernel route lookup is multipath")
			}
			if attribute.Attr.Type == unix.RTA_OIF {
				if len(attribute.Value) != 4 {
					return "", fmt.Errorf("kernel route output interface is malformed")
				}
				candidate := int(binary.NativeEndian.Uint32(attribute.Value))
				if oif != 0 && oif != candidate {
					return "", fmt.Errorf("kernel route lookup returned multiple interfaces")
				}
				oif = candidate
			}
		}
	}
	if oif == 0 {
		return "", fmt.Errorf("kernel route lookup returned no output interface")
	}
	networkInterface, err := net.InterfaceByIndex(oif)
	if err != nil {
		return "", err
	}
	ownsSource := false
	addresses, err := networkInterface.Addrs()
	if err != nil {
		return "", err
	}
	for _, value := range addresses {
		prefix, parseErr := netip.ParsePrefix(value.String())
		if parseErr == nil && prefix.Addr().Unmap() == source.Unmap() {
			ownsSource = true
		}
	}
	if !ownsSource {
		return "", fmt.Errorf("kernel route output interface does not own selected source")
	}
	return networkInterface.Name, nil
}

func writeRouteAttribute(buffer *bytes.Buffer, kind uint16, value []byte) {
	length := unix.SizeofRtAttr + len(value)
	_ = binary.Write(buffer, binary.NativeEndian, unix.RtAttr{Len: uint16(length), Type: kind})
	buffer.Write(value)
	for buffer.Len()%4 != 0 {
		buffer.WriteByte(0)
	}
}
