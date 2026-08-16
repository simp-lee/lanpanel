//go:build linux

package control

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"net"
	"testing"
)

func TestSTUNRelayPreservesPublicPeerIdentity(t *testing.T) {
	transaction := []byte("123456789012")
	request := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, transaction...)
	response := append([]byte{0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42}, transaction...)
	response = append(response, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	peer := &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 54321}
	if err := rewriteSTUNMappedAddress(response, request, peer); err != nil {
		t.Fatal(err)
	}
	port := int((uint16(response[26])<<8 | uint16(response[27])) ^ 0x2112)
	address := append([]byte(nil), response[28:32]...)
	for index, value := range []byte{0x21, 0x12, 0xa4, 0x42} {
		address[index] ^= value
	}
	if port != peer.Port || !bytes.Equal(address, peer.IP.To4()) {
		t.Fatalf("mapped peer=%v:%d want=%v", net.IP(address), port, peer)
	}
	fingerprinted := append([]byte(nil), response...)
	fingerprinted[2], fingerprinted[3] = 0, 20
	fingerprinted = append(fingerprinted, 0x80, 0x28, 0, 4, 0, 0, 0, 0)
	if err := rewriteSTUNMappedAddress(fingerprinted, request, peer); err != nil {
		t.Fatal(err)
	}
	if got, want := binary.BigEndian.Uint32(fingerprinted[len(fingerprinted)-4:]), crc32.ChecksumIEEE(fingerprinted[:len(fingerprinted)-8])^uint32(0x5354554e); got != want {
		t.Fatalf("fingerprint=%08x want=%08x", got, want)
	}
	changed := append([]byte(nil), response...)
	changed[8] ^= 1
	if rewriteSTUNMappedAddress(changed, request, peer) == nil {
		t.Fatal("cross-transaction STUN response accepted")
	}
}
