//go:build linux

package process

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"lanpanel/internal/confinement"
	"lanpanel/internal/domain"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	bpfCommandMapCreate     = 0
	bpfMapLookup            = 1
	bpfMapUpdate            = 2
	bpfMapDelete            = 3
	bpfProgLoad             = 5
	bpfObjectPin            = 6
	bpfObjectGet            = 7
	bpfCommandProgramFDByID = 13
	bpfCommandObjectInfo    = 15
	bpfCommandLinkCreate    = 28
	bpfMapTypeHash          = 1
	bpfProgramTypeLSM       = 29
	bpfAttachLSMMAC         = 27
	bpfHelperMapLookup      = 1
	bpfHelperCurrentUIDGID  = 15
	bpfPseudoMapFD          = 1
	bpfLinkTypeTracing      = 2
)

type bpfInstruction struct {
	Code      uint8
	Registers uint8
	Offset    int16
	Immediate int32
}
type bpfMapCreate struct {
	MapType               uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	InnerMapFD            uint32
	NUMANode              uint32
	MapName               [16]byte
	MapIfindex            uint32
	BTFFD                 uint32
	BTFKeyTypeID          uint32
	BTFValueTypeID        uint32
	BTFVmlinuxValueTypeID uint32
	MapExtra              uint64
	ValueTypeBTFObjectFD  int32
	MapTokenFD            int32
}
type bpfMapElement struct {
	MapFD   uint32
	Padding uint32
	Key     uint64
	Value   uint64
	Flags   uint64
}
type bpfObjectInfo struct {
	BpfFD      uint32
	InfoLength uint32
	Info       uint64
}
type bpfIDOpen struct {
	ID        uint32
	NextID    uint32
	OpenFlags uint32
}
type bpfMapInfo struct {
	MapType    uint32
	ID         uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
	Name       [16]byte
}
type bpfLinkInfo struct {
	LinkType       uint32
	ID             uint32
	ProgramID      uint32
	Padding        uint32
	AttachType     uint32
	TargetObjectID uint32
	TargetBTFID    uint32
	Padding2       uint32
}
type bpfProgramInfo struct {
	ProgramType              uint32
	ID                       uint32
	Tag                      [8]byte
	JitedLength              uint32
	TranslatedLength         uint32
	JitedInstructions        uint64
	TranslatedInstructions   uint64
	LoadTime                 uint64
	CreatedUID               uint32
	MapCount                 uint32
	MapIDs                   uint64
	Name                     [16]byte
	Ifindex                  uint32
	GPLCompatible            uint32
	NetnsDevice              uint64
	NetnsInode               uint64
	JitedSymbolCount         uint32
	JitedFunctionLengthCount uint32
	JitedSymbols             uint64
	JitedFunctionLengths     uint64
	BTFID                    uint32
	FunctionInfoRecordSize   uint32
	FunctionInfo             uint64
	FunctionInfoCount        uint32
	LineInfoCount            uint32
	LineInfo                 uint64
	JitedLineInfo            uint64
	JitedLineInfoCount       uint32
	LineInfoRecordSize       uint32
	JitedLineInfoRecordSize  uint32
	ProgramTagCount          uint32
	ProgramTags              uint64
	RuntimeNS                uint64
	RunCount                 uint64
	RecursionMisses          uint64
	VerifiedInstructions     uint32
	AttachBTFObjectID        uint32
	AttachBTFID              uint32
}
type bpfProgramLoad struct {
	ProgramType            uint32
	InstructionCount       uint32
	Instructions           uint64
	License                uint64
	LogLevel               uint32
	LogSize                uint32
	LogBuffer              uint64
	KernelVersion          uint32
	ProgramFlags           uint32
	ProgramName            [16]byte
	ProgramIfindex         uint32
	ExpectedAttachType     uint32
	ProgramBTFFD           uint32
	FunctionInfoRecordSize uint32
	FunctionInfo           uint64
	FunctionInfoCount      uint32
	LineInfoRecordSize     uint32
	LineInfo               uint64
	LineInfoCount          uint32
	AttachBTFID            uint32
	AttachBTFObjectFD      uint32
}
type bpfLinkCreate struct {
	ProgramFD  uint32
	TargetFD   uint32
	AttachType uint32
	Flags      uint32
}
type bpfObjectPath struct {
	Pathname  uint64
	BpfFD     uint32
	FileFlags uint32
	PathFD    int32
	Padding   uint32
}

var listenGuardMu sync.Mutex

type kernelBTFLayout struct {
	SocketSK           int16
	SockFamily         int16
	ListenFunctionID   uint32
	ListenReturnOffset int16
}

func ensureListenGuard(resourceID string, uid uint32, policy confinement.UnitPolicy) error {
	listenGuardMu.Lock()
	defer listenGuardMu.Unlock()
	if uid == 0 || policy.BindListenPolicy != "systemd_bind_deny_bpf_lsm_listen_v1" {
		return fmt.Errorf("managed listen guard authority is invalid")
	}
	if len(resourceID) != 36 || !strings.HasPrefix(resourceID, "res_") || len(policy.Digest) != 71 {
		return fmt.Errorf("managed listen guard identity is incomplete")
	}
	if err := ensureBPFDirectory(); err != nil {
		return err
	}
	layout, err := readKernelBTFLayout("/sys/kernel/btf/vmlinux")
	if err != nil {
		return err
	}
	template := listenGuardInstructions(0, layout)
	version := listenGuardVersion(template, layout)
	mapPath, linkPath := listenGuardPaths(version)
	if err := rejectStaleListenGuardPins(mapPath, linkPath); err != nil {
		return err
	}
	mapFD, err := openOrCreateListenGuardMap(mapPath)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(mapFD) }()
	if err := ensureListenGuardLink(linkPath, mapFD, layout); err != nil {
		return err
	}
	return updateListenGuardUID(mapFD, uid, true)
}

func verifyListenGuard(resourceID string, uid uint32, policy confinement.UnitPolicy) error {
	listenGuardMu.Lock()
	defer listenGuardMu.Unlock()
	if uid == 0 || policy.BindListenPolicy != "systemd_bind_deny_bpf_lsm_listen_v1" || len(resourceID) != 36 || !strings.HasPrefix(resourceID, "res_") || len(policy.Digest) != 71 {
		return NewRuntimeViolation(RuntimeViolationPolicyInvalid, fmt.Errorf("managed listen guard authority is invalid"))
	}
	layout, err := readKernelBTFLayout("/sys/kernel/btf/vmlinux")
	if err != nil {
		return err
	}
	mapPath, linkPath := listenGuardPaths(listenGuardVersion(listenGuardInstructions(0, layout), layout))
	if err := rejectStaleListenGuardPins(mapPath, linkPath); err != nil {
		return err
	}
	mapFD, err := getPinnedBPF(mapPath)
	if errors.Is(err, unix.ENOENT) {
		return NewRuntimeViolation(RuntimeViolationPolicyInvalid, fmt.Errorf("managed listen guard map is absent"))
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(mapFD) }()
	if err := verifyListenGuardMap(mapFD); err != nil {
		return err
	}
	linkFD, err := getPinnedBPF(linkPath)
	if errors.Is(err, unix.ENOENT) {
		return NewRuntimeViolation(RuntimeViolationPolicyInvalid, fmt.Errorf("managed listen guard link is absent"))
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(linkFD) }()
	if err := verifyListenGuardLink(linkFD, mapFD, layout); err != nil {
		return err
	}
	present, err := listenGuardUIDPresent(mapFD, uid)
	if err != nil {
		return err
	}
	if !present {
		return NewRuntimeViolation(RuntimeViolationPolicyInvalid, fmt.Errorf("managed listen guard omits application UID"))
	}
	return nil
}

func InitializeListenGuards(running []domain.ProcessBundle) error {
	listenGuardMu.Lock()
	defer listenGuardMu.Unlock()
	if err := ensureBPFDirectory(); err != nil {
		return err
	}
	layout, err := readKernelBTFLayout("/sys/kernel/btf/vmlinux")
	if err != nil {
		return err
	}
	mapPath, linkPath := listenGuardPaths(listenGuardVersion(listenGuardInstructions(0, layout), layout))
	if err := rejectStaleListenGuardPins(mapPath, linkPath); err != nil {
		return err
	}
	mapFD, err := openOrCreateListenGuardMap(mapPath)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(mapFD) }()
	if err := ensureListenGuardLink(linkPath, mapFD, layout); err != nil {
		return err
	}
	for _, bundle := range running {
		if bundle.ApplicationUID == 0 {
			return fmt.Errorf("durable running process omits application UID")
		}
		if err := updateListenGuardUID(mapFD, bundle.ApplicationUID, true); err != nil {
			return err
		}
	}
	return nil
}

func releaseListenGuardUID(uid uint32) error {
	listenGuardMu.Lock()
	defer listenGuardMu.Unlock()
	if uid == 0 {
		return fmt.Errorf("managed listen guard UID is invalid")
	}
	layout, err := readKernelBTFLayout("/sys/kernel/btf/vmlinux")
	if err != nil {
		return err
	}
	mapPath, linkPath := listenGuardPaths(listenGuardVersion(listenGuardInstructions(0, layout), layout))
	if err := rejectStaleListenGuardPins(mapPath, linkPath); err != nil {
		return err
	}
	mapFD, err := getPinnedBPF(mapPath)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(mapFD) }()
	if err := verifyListenGuardMap(mapFD); err != nil {
		return err
	}
	return updateListenGuardUID(mapFD, uid, false)
}

func listenGuardPaths(version string) (string, string) {
	return filepath.Join("/sys/fs/bpf/lanpanel", "listen-map-"+version[:24]), filepath.Join("/sys/fs/bpf/lanpanel", "listen-link-"+version[:24])
}

func rejectStaleListenGuardPins(mapPath, linkPath string) error {
	entries, err := os.ReadDir("/sys/fs/bpf/lanpanel")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "listen-") && name != filepath.Base(mapPath) && name != filepath.Base(linkPath) {
			return NewRuntimeViolation(RuntimeViolationPolicyInvalid, fmt.Errorf("stale managed listen guard pin requires diagnostics, export, and clean-host rebuild"))
		}
	}
	return nil
}

func openOrCreateListenGuardMap(path string) (int, error) {
	if fd, err := getPinnedBPF(path); err == nil {
		if err := verifyListenGuardMap(fd); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		return fd, nil
	} else if !errors.Is(err, unix.ENOENT) {
		return -1, err
	}
	attribute := bpfMapCreate{MapType: bpfMapTypeHash, KeySize: 4, ValueSize: 1, MaxEntries: 4096}
	copy(attribute.MapName[:], "lp_listen_uids")
	fd, _, errno := unix.Syscall(unix.SYS_BPF, bpfCommandMapCreate, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 {
		return -1, fmt.Errorf("create managed listen UID map: %w", errno)
	}
	if err := pinBPF(path, int(fd)); err != nil {
		_ = unix.Close(int(fd))
		return -1, err
	}
	if err := verifyListenGuardMap(int(fd)); err != nil {
		_ = unix.Close(int(fd))
		return -1, err
	}
	return int(fd), nil
}

func verifyListenGuardMap(fd int) error {
	var info bpfMapInfo
	attribute := bpfObjectInfo{BpfFD: uint32(fd), InfoLength: uint32(unsafe.Sizeof(info)), Info: uint64(uintptr(unsafe.Pointer(&info)))}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfCommandObjectInfo, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 {
		return fmt.Errorf("inspect managed listen UID map: %w", errno)
	}
	if info.MapType != bpfMapTypeHash || info.KeySize != 4 || info.ValueSize != 1 || info.MaxEntries != 4096 || info.MapFlags != 0 || strings.TrimRight(string(info.Name[:]), "\x00") != "lp_listen_uids" {
		return NewRuntimeViolation(RuntimeViolationPolicyInvalid, fmt.Errorf("managed listen UID map identity differs"))
	}
	return nil
}

func ensureListenGuardLink(path string, mapFD int, layout kernelBTFLayout) error {
	if fd, err := getPinnedBPF(path); err == nil {
		verifyErr := verifyListenGuardLink(fd, mapFD, layout)
		closeErr := unix.Close(fd)
		return errors.Join(verifyErr, closeErr)
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	instructions := listenGuardInstructions(mapFD, layout)
	license := append([]byte("GPL"), 0)
	log := make([]byte, 64<<10)
	attribute := bpfProgramLoad{ProgramType: bpfProgramTypeLSM, InstructionCount: uint32(len(instructions)), Instructions: uint64(uintptr(unsafe.Pointer(&instructions[0]))), License: uint64(uintptr(unsafe.Pointer(&license[0]))), LogLevel: 1, LogSize: uint32(len(log)), LogBuffer: uint64(uintptr(unsafe.Pointer(&log[0]))), ExpectedAttachType: bpfAttachLSMMAC, AttachBTFID: layout.ListenFunctionID}
	copy(attribute.ProgramName[:], "lp_listen_map")
	programFD, _, errno := unix.Syscall(unix.SYS_BPF, bpfProgLoad, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 {
		return fmt.Errorf("load managed listen BPF LSM: %w: %s", errno, strings.TrimRight(string(log), "\x00"))
	}
	defer func() { _ = unix.Close(int(programFD)) }()
	linkAttribute := bpfLinkCreate{ProgramFD: uint32(programFD), AttachType: bpfAttachLSMMAC}
	linkFD, _, errno := unix.Syscall(unix.SYS_BPF, bpfCommandLinkCreate, uintptr(unsafe.Pointer(&linkAttribute)), unsafe.Sizeof(linkAttribute))
	if errno != 0 {
		return fmt.Errorf("attach managed listen BPF LSM: %w", errno)
	}
	defer func() { _ = unix.Close(int(linkFD)) }()
	if err := pinBPF(path, int(linkFD)); err != nil {
		return err
	}
	fd, err := getPinnedBPF(path)
	if err != nil {
		return fmt.Errorf("reopen managed listen BPF link: %w", err)
	}
	return unix.Close(fd)
}

func verifyListenGuardLink(linkFD, mapFD int, layout kernelBTFLayout) error {
	var link bpfLinkInfo
	attribute := bpfObjectInfo{BpfFD: uint32(linkFD), InfoLength: uint32(unsafe.Sizeof(link)), Info: uint64(uintptr(unsafe.Pointer(&link)))}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfCommandObjectInfo, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 {
		return fmt.Errorf("inspect managed listen BPF link: %w", errno)
	}
	if link.LinkType != bpfLinkTypeTracing || link.AttachType != bpfAttachLSMMAC || link.TargetBTFID != layout.ListenFunctionID || link.ProgramID == 0 {
		return NewRuntimeViolation(RuntimeViolationPolicyInvalid, fmt.Errorf("managed listen BPF link identity differs"))
	}
	programFD, _, errno := unix.Syscall(unix.SYS_BPF, bpfCommandProgramFDByID, uintptr(unsafe.Pointer(&bpfIDOpen{ID: link.ProgramID})), unsafe.Sizeof(bpfIDOpen{}))
	if errno != 0 {
		return fmt.Errorf("open managed listen BPF program: %w", errno)
	}
	defer func() { _ = unix.Close(int(programFD)) }()
	var program bpfProgramInfo
	mapIDs := make([]uint32, 1)
	program.MapCount = 1
	program.MapIDs = uint64(uintptr(unsafe.Pointer(&mapIDs[0])))
	attribute = bpfObjectInfo{BpfFD: uint32(programFD), InfoLength: uint32(unsafe.Sizeof(program)), Info: uint64(uintptr(unsafe.Pointer(&program)))}
	_, _, errno = unix.Syscall(unix.SYS_BPF, bpfCommandObjectInfo, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 {
		return fmt.Errorf("inspect managed listen BPF program: %w", errno)
	}
	var mapInfo bpfMapInfo
	mapAttribute := bpfObjectInfo{BpfFD: uint32(mapFD), InfoLength: uint32(unsafe.Sizeof(mapInfo)), Info: uint64(uintptr(unsafe.Pointer(&mapInfo)))}
	_, _, errno = unix.Syscall(unix.SYS_BPF, bpfCommandObjectInfo, uintptr(unsafe.Pointer(&mapAttribute)), unsafe.Sizeof(mapAttribute))
	if errno != 0 {
		return fmt.Errorf("inspect expected managed listen map: %w", errno)
	}
	if program.ProgramType != bpfProgramTypeLSM || program.AttachBTFID != layout.ListenFunctionID || program.CreatedUID != 0 || program.MapCount != 1 || mapIDs[0] == 0 || mapIDs[0] != mapInfo.ID || strings.TrimRight(string(program.Name[:]), "\x00") != "lp_listen_map" {
		return NewRuntimeViolation(RuntimeViolationPolicyInvalid, fmt.Errorf("managed listen BPF program identity differs"))
	}
	return nil
}

func listenGuardUIDPresent(mapFD int, uid uint32) (bool, error) {
	key := uid
	value := byte(0)
	attribute := bpfMapElement{MapFD: uint32(mapFD), Key: uint64(uintptr(unsafe.Pointer(&key))), Value: uint64(uintptr(unsafe.Pointer(&value)))}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfMapLookup, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errors.Is(errno, unix.ENOENT) {
		return false, nil
	}
	if errno != 0 {
		return false, fmt.Errorf("read managed listen UID authority: %w", errno)
	}
	if value != 1 {
		return false, NewRuntimeViolation(RuntimeViolationPolicyInvalid, fmt.Errorf("managed listen UID authority value is invalid"))
	}
	return true, nil
}

func updateListenGuardUID(mapFD int, uid uint32, present bool) error {
	key := uid
	value := byte(1)
	attribute := bpfMapElement{MapFD: uint32(mapFD), Key: uint64(uintptr(unsafe.Pointer(&key))), Value: uint64(uintptr(unsafe.Pointer(&value)))}
	command := uintptr(bpfMapUpdate)
	if !present {
		command = bpfMapDelete
		attribute.Value = 0
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, command, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if !present && errors.Is(errno, unix.ENOENT) {
		return nil
	}
	if errno != 0 {
		return fmt.Errorf("update managed listen UID authority: %w", errno)
	}
	return nil
}

func listenGuardVersion(instructions []bpfInstruction, layout kernelBTFLayout) string {
	hash := sha256.New()
	for _, instruction := range instructions {
		_ = binary.Write(hash, binary.LittleEndian, instruction)
	}
	_ = binary.Write(hash, binary.LittleEndian, layout.ListenFunctionID)
	return hex.EncodeToString(hash.Sum(nil))
}

func ensureBPFDirectory() error {
	const path = "/sys/fs/bpf/lanpanel"
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("managed BPF pin directory is unsafe")
	}
	return nil
}

func pinBPF(path string, fd int) error {
	bytes := append([]byte(path), 0)
	attribute := bpfObjectPath{Pathname: uint64(uintptr(unsafe.Pointer(&bytes[0]))), BpfFD: uint32(fd)}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfObjectPin, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 {
		return fmt.Errorf("pin managed listen BPF link: %w", errno)
	}
	return nil
}

func getPinnedBPF(path string) (int, error) {
	bytes := append([]byte(path), 0)
	attribute := bpfObjectPath{Pathname: uint64(uintptr(unsafe.Pointer(&bytes[0])))}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, bpfObjectGet, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func listenGuardInstructions(mapFD int, layout kernelBTFLayout) []bpfInstruction {
	return []bpfInstruction{
		{Code: 0x61, Registers: 7 | (1 << 4), Offset: layout.ListenReturnOffset},
		{Code: 0x15, Registers: 7, Offset: 2},
		{Code: 0xbc, Registers: 0 | (7 << 4)},
		{Code: 0x95},
		{Code: 0x79, Registers: 6 | (1 << 4)},
		{Code: 0x85, Immediate: bpfHelperCurrentUIDGID},
		{Code: 0xbc, Registers: 0},
		{Code: 0x63, Registers: 10, Offset: -4},
		{Code: 0x18, Registers: 1 | (bpfPseudoMapFD << 4), Immediate: int32(mapFD)},
		{},
		{Code: 0xbf, Registers: 2 | (10 << 4)},
		{Code: 0x07, Registers: 2, Immediate: -4},
		{Code: 0x85, Immediate: bpfHelperMapLookup},
		{Code: 0x15, Registers: 0, Offset: 5},
		{Code: 0x79, Registers: 2 | (6 << 4), Offset: layout.SocketSK},
		{Code: 0x69, Registers: 2 | (2 << 4), Offset: layout.SockFamily},
		{Code: 0x15, Registers: 2, Offset: 3, Immediate: unix.AF_INET},
		{Code: 0x15, Registers: 2, Offset: 2, Immediate: unix.AF_INET6},
		{Code: 0xb7, Registers: 0},
		{Code: 0x95},
		{Code: 0xb7, Registers: 0, Immediate: -int32(unix.EACCES)},
		{Code: 0x95},
	}
}

func readKernelBTFLayout(path string) (kernelBTFLayout, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return kernelBTFLayout{}, err
	}
	if len(data) < 24 || len(data) > 64<<20 || binary.LittleEndian.Uint16(data[:2]) != 0xeb9f {
		return kernelBTFLayout{}, fmt.Errorf("kernel BTF header is invalid")
	}
	headerLength := int(binary.LittleEndian.Uint32(data[4:8]))
	typeStart := headerLength + int(binary.LittleEndian.Uint32(data[8:12]))
	typeEnd := typeStart + int(binary.LittleEndian.Uint32(data[12:16]))
	stringStart := headerLength + int(binary.LittleEndian.Uint32(data[16:20]))
	stringEnd := stringStart + int(binary.LittleEndian.Uint32(data[20:24]))
	if headerLength < 24 || typeStart < headerLength || typeEnd > len(data) || stringStart < headerLength || stringEnd > len(data) {
		return kernelBTFLayout{}, fmt.Errorf("kernel BTF sections are invalid")
	}
	stringsData := data[stringStart:stringEnd]
	name := func(offset uint32) (string, error) {
		if int(offset) >= len(stringsData) {
			return "", fmt.Errorf("kernel BTF string offset invalid")
		}
		tail := stringsData[offset:]
		end := 0
		for end < len(tail) && tail[end] != 0 {
			end++
		}
		if end == len(tail) {
			return "", fmt.Errorf("kernel BTF string unterminated")
		}
		return string(tail[:end]), nil
	}
	layout := kernelBTFLayout{SocketSK: -1, SockFamily: -1, ListenReturnOffset: -1}
	functionProto := uint32(0)
	protoParameters := map[uint32]int{}
	offset, typeID := typeStart, uint32(1)
	for offset < typeEnd {
		if offset+12 > typeEnd {
			return kernelBTFLayout{}, fmt.Errorf("kernel BTF type truncated")
		}
		nameOffset := binary.LittleEndian.Uint32(data[offset:])
		info := binary.LittleEndian.Uint32(data[offset+4:])
		kind := (info >> 24) & 0x1f
		vlen := int(info & 0xffff)
		kindFlag := info>>31 != 0
		typeName, err := name(nameOffset)
		if err != nil {
			return kernelBTFLayout{}, err
		}
		extra := 0
		switch kind {
		case 1:
			extra = 4
		case 3:
			extra = 12
		case 4, 5:
			extra = vlen * 12
		case 6:
			extra = vlen * 8
		case 13:
			extra = vlen * 8
		case 14:
			extra = 4
		case 15:
			extra = vlen * 12
		case 17:
			extra = 4
		case 19:
			extra = vlen * 12
		}
		if offset+12+extra > typeEnd {
			return kernelBTFLayout{}, fmt.Errorf("kernel BTF type payload truncated")
		}
		if kind == 4 && (typeName == "socket" || typeName == "sock_common") {
			for member := 0; member < vlen; member++ {
				base := offset + 12 + member*12
				memberName, err := name(binary.LittleEndian.Uint32(data[base:]))
				if err != nil {
					return kernelBTFLayout{}, err
				}
				bits := binary.LittleEndian.Uint32(data[base+8:])
				if kindFlag {
					bits &= 0x00ffffff
				}
				target := typeName == "socket" && memberName == "sk" || typeName == "sock_common" && memberName == "skc_family"
				if !target {
					continue
				}
				if bits%8 != 0 || bits/8 > 32767 {
					return kernelBTFLayout{}, fmt.Errorf("kernel BTF managed member offset unsupported")
				}
				if typeName == "socket" {
					layout.SocketSK = int16(bits / 8)
				} else {
					layout.SockFamily = int16(bits / 8)
				}
			}
		}
		if kind == 13 {
			protoParameters[typeID] = vlen
		}
		if kind == 12 && typeName == "bpf_lsm_socket_listen" {
			layout.ListenFunctionID = typeID
			functionProto = binary.LittleEndian.Uint32(data[offset+8:])
		}
		offset += 12 + extra
		typeID++
	}
	parameters, present := protoParameters[functionProto]
	if present && parameters >= 2 {
		layout.ListenReturnOffset = int16(parameters * 8)
	}
	if offset != typeEnd || layout.SocketSK < 0 || layout.SockFamily < 0 || layout.ListenFunctionID == 0 || layout.ListenReturnOffset != 16 {
		return kernelBTFLayout{}, fmt.Errorf("kernel BTF omits managed listen hook layout: socket_sk=%d sock_family=%d listen_id=%d return_offset=%d", layout.SocketSK, layout.SockFamily, layout.ListenFunctionID, layout.ListenReturnOffset)
	}
	return layout, nil
}
