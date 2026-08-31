package qualification

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestProbeSTUNEndpointValidatesBindingResponse(t *testing.T) {
	tests := []struct {
		name     string
		response func([]byte, *net.UDPAddr) []byte
		wantErr  bool
	}{
		{
			name: "valid XOR mapped response",
			response: func(request []byte, peer *net.UDPAddr) []byte {
				return qualificationSTUNResponse(request, 0x0101,
					qualificationSTUNAttribute(0x8022, []byte("fixture")),
					qualificationMappedAttribute(peer, true),
				)
			},
		},
		{
			name: "valid mapped response",
			response: func(request []byte, peer *net.UDPAddr) []byte {
				return qualificationSTUNResponse(request, 0x0101, qualificationMappedAttribute(peer, false))
			},
		},
		{
			name: "binding error response",
			response: func(request []byte, peer *net.UDPAddr) []byte {
				return qualificationSTUNResponse(request, 0x0111, qualificationMappedAttribute(peer, true))
			},
			wantErr: true,
		},
		{
			name: "empty success response",
			response: func(request []byte, _ *net.UDPAddr) []byte {
				return qualificationSTUNResponse(request, 0x0101)
			},
			wantErr: true,
		},
		{
			name: "declared length mismatch",
			response: func(request []byte, peer *net.UDPAddr) []byte {
				response := qualificationSTUNResponse(request, 0x0101, qualificationMappedAttribute(peer, true))
				binary.BigEndian.PutUint16(response[2:4], 0)
				return response
			},
			wantErr: true,
		},
		{
			name: "out of bounds attribute",
			response: func(request []byte, _ *net.UDPAddr) []byte {
				attribute := make([]byte, 4)
				binary.BigEndian.PutUint16(attribute[0:2], 0x0020)
				binary.BigEndian.PutUint16(attribute[2:4], 8)
				return qualificationSTUNResponse(request, 0x0101, attribute)
			},
			wantErr: true,
		},
		{
			name: "malformed mapped address",
			response: func(request []byte, _ *net.UDPAddr) []byte {
				value := []byte{0, 0x03, 0x12, 0x34, 127, 0, 0, 1}
				return qualificationSTUNResponse(request, 0x0101, qualificationSTUNAttribute(0x0020, value))
			},
			wantErr: true,
		},
		{
			name: "duplicate mapped addresses",
			response: func(request []byte, peer *net.UDPAddr) []byte {
				return qualificationSTUNResponse(request, 0x0101, qualificationMappedAttribute(peer, true), qualificationMappedAttribute(peer, false))
			},
			wantErr: true,
		},
		{
			name: "wrong cookie",
			response: func(request []byte, peer *net.UDPAddr) []byte {
				response := qualificationSTUNResponse(request, 0x0101, qualificationMappedAttribute(peer, true))
				binary.BigEndian.PutUint32(response[4:8], 0x2112a443)
				return response
			},
			wantErr: true,
		},
		{
			name: "wrong transaction",
			response: func(request []byte, peer *net.UDPAddr) []byte {
				response := qualificationSTUNResponse(request, 0x0101, qualificationMappedAttribute(peer, true))
				response[8] ^= 0xff
				return response
			},
			wantErr: true,
		},
		{
			name: "wrong mapped source",
			response: func(request []byte, peer *net.UDPAddr) []byte {
				wrong := *peer
				wrong.IP = net.IPv4(127, 0, 0, 2)
				return qualificationSTUNResponse(request, 0x0101, qualificationMappedAttribute(&wrong, true))
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := runQualificationSTUNFixture(t, test.response)
			if (err != nil) != test.wantErr {
				t.Fatalf("probeSTUNEndpoint() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func runQualificationSTUNFixture(t *testing.T, response func([]byte, *net.UDPAddr) []byte) ([]byte, error) {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	serverResult := make(chan error, 1)
	go func() {
		_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 2048)
		count, peer, err := listener.ReadFromUDP(buffer)
		if err != nil {
			serverResult <- err
			return
		}
		request := buffer[:count]
		if count != 20 || binary.BigEndian.Uint16(request[0:2]) != 0x0001 || binary.BigEndian.Uint16(request[2:4]) != 0 || binary.BigEndian.Uint32(request[4:8]) != 0x2112a442 {
			serverResult <- fmt.Errorf("invalid binding request")
			return
		}
		_, err = listener.WriteToUDP(response(request, peer), peer)
		serverResult <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	probeResponse, probeErr := probeSTUNEndpoint(ctx, listener.LocalAddr().String(), netip.MustParseAddr("127.0.0.1"))
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	return probeResponse, probeErr
}

func qualificationSTUNResponse(request []byte, messageType uint16, attributes ...[]byte) []byte {
	length := 0
	for _, attribute := range attributes {
		length += len(attribute)
	}
	response := make([]byte, 20, 20+length)
	binary.BigEndian.PutUint16(response[0:2], messageType)
	binary.BigEndian.PutUint16(response[2:4], uint16(length))
	binary.BigEndian.PutUint32(response[4:8], 0x2112a442)
	copy(response[8:20], request[8:20])
	for _, attribute := range attributes {
		response = append(response, attribute...)
	}
	return response
}

func qualificationSTUNAttribute(attributeType uint16, value []byte) []byte {
	attribute := make([]byte, 4+((len(value)+3)&^3))
	binary.BigEndian.PutUint16(attribute[0:2], attributeType)
	binary.BigEndian.PutUint16(attribute[2:4], uint16(len(value)))
	copy(attribute[4:], value)
	return attribute
}

func qualificationMappedAttribute(peer *net.UDPAddr, xor bool) []byte {
	value := make([]byte, 8)
	value[1] = 0x01
	port := uint16(peer.Port)
	if xor {
		port ^= 0x2112
	}
	binary.BigEndian.PutUint16(value[2:4], port)
	copy(value[4:], peer.IP.To4())
	attributeType := uint16(0x0001)
	if xor {
		attributeType = 0x0020
		for index, mask := range []byte{0x21, 0x12, 0xa4, 0x42} {
			value[4+index] ^= mask
		}
	}
	return qualificationSTUNAttribute(attributeType, value)
}
