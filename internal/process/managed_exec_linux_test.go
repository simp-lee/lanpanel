//go:build linux

package process

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestListenGuardUsesKernelBTFAndDeniesOnlyINETForExactUID(t *testing.T) {
	layout, err := readKernelBTFLayout("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Fatal(err)
	}
	if layout.SocketSK < 0 || layout.SockFamily < 0 || layout.ListenFunctionID == 0 || layout.ListenReturnOffset != 16 {
		t.Fatalf("layout=%#v", layout)
	}
	mapFD := 12345
	instructions := listenGuardInstructions(mapFD, layout)
	if len(instructions) != 22 || instructions[0].Offset != 16 || instructions[1].Offset != 2 || instructions[2].Registers != 0|(7<<4) || instructions[5].Immediate != bpfHelperCurrentUIDGID || instructions[7].Code != 0x63 || instructions[8].Immediate != int32(mapFD) || instructions[8].Registers != 1|(bpfPseudoMapFD<<4) || instructions[12].Immediate != bpfHelperMapLookup || instructions[13].Offset != 5 || instructions[16].Immediate != unix.AF_INET || instructions[17].Immediate != unix.AF_INET6 || instructions[20].Immediate != -int32(unix.EACCES) {
		t.Fatalf("instructions=%#v", instructions)
	}
}
