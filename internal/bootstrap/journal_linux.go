//go:build linux

package bootstrap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const journalSlotBytes = MaximumJournalBytes + 32
const journalFileBytes = journalSlotBytes * 2

type journalStore struct {
	fd       int
	dirFD    int
	path     string
	owner    uint32
	group    uint32
	sequence uint64
	slot     int
}

func createJournal(path string, owner, group uint32, value Journal) (*journalStore, error) {
	if value.Sequence != 1 || value.Phase != PhasePrepared {
		return nil, fmt.Errorf("first bootstrap journal phase is invalid")
	}
	store, err := openJournalDescriptors(path, owner, group, true)
	if err != nil {
		return nil, err
	}
	data, err := encodeJournalSlot(value)
	if err != nil {
		store.close()
		return nil, err
	}
	if err := unix.Ftruncate(store.fd, journalFileBytes); err != nil {
		store.close()
		return nil, err
	}
	for index := range 2 {
		if written, err := unix.Pwrite(store.fd, data, int64(index*journalSlotBytes)); err != nil || written != len(data) {
			store.close()
			return nil, fmt.Errorf("initialize bootstrap journal slot")
		}
	}
	if err := unix.Fsync(store.fd); err != nil || unix.Fsync(store.dirFD) != nil {
		store.close()
		return nil, fmt.Errorf("sync first bootstrap journal")
	}
	store.sequence, store.slot = 1, 1
	return store, nil
}

func openJournal(path string, owner, group uint32) (*journalStore, Journal, error) {
	store, err := openJournalDescriptors(path, owner, group, false)
	if err != nil {
		return nil, Journal{}, err
	}
	value, slot, err := store.load()
	if err != nil {
		store.close()
		return nil, Journal{}, err
	}
	store.sequence, store.slot = value.Sequence, slot
	return store, value, nil
}

func openJournalDescriptors(path string, owner, group uint32, create bool) (*journalStore, error) {
	parent := filepath.Dir(path)
	dirFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var parentStat unix.Stat_t
	if err := unix.Fstat(dirFD, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Uid != owner || parentStat.Gid != group || parentStat.Mode&0o022 != 0 {
		_ = unix.Close(dirFD)
		return nil, fmt.Errorf("bootstrap journal parent is unsafe")
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(dirFD, filepath.Base(path), flags, 0o600)
	if err != nil {
		_ = unix.Close(dirFD)
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || stat.Gid != group || stat.Mode&0o777 != 0o600 || !create && stat.Size != journalFileBytes {
		_ = unix.Close(fd)
		_ = unix.Close(dirFD)
		return nil, fmt.Errorf("bootstrap journal identity is unsafe")
	}
	return &journalStore{fd: fd, dirFD: dirFD, path: path, owner: owner, group: group}, nil
}

func (store *journalStore) load() (Journal, int, error) {
	best := Journal{}
	bestSlot := -1
	for slot := range 2 {
		data := make([]byte, journalSlotBytes)
		if read, err := unix.Pread(store.fd, data, int64(slot*journalSlotBytes)); err != nil || read != len(data) {
			continue
		}
		value, err := decodeJournalSlot(data)
		if err == nil && value.Sequence > best.Sequence {
			best, bestSlot = value, slot
		}
	}
	if bestSlot < 0 {
		return Journal{}, 0, fmt.Errorf("bootstrap journal has no valid durable slot")
	}
	return best, bestSlot, nil
}

func (store *journalStore) update(value Journal) error {
	if store == nil || value.Sequence != store.sequence+1 {
		return fmt.Errorf("bootstrap journal sequence must advance exactly once")
	}
	data, err := encodeJournalSlot(value)
	if err != nil {
		return err
	}
	slot := 1 - store.slot
	if written, err := unix.Pwrite(store.fd, data, int64(slot*journalSlotBytes)); err != nil || written != len(data) {
		return fmt.Errorf("write bootstrap journal slot")
	}
	if err := unix.Fsync(store.fd); err != nil {
		return err
	}
	loaded, loadedSlot, err := store.load()
	if err != nil || loaded.Sequence != value.Sequence || loadedSlot != slot {
		return fmt.Errorf("bootstrap journal update did not verify")
	}
	store.sequence, store.slot = value.Sequence, slot
	return nil
}

func (store *journalStore) close() error {
	if store == nil {
		return nil
	}
	return errors.Join(unix.Close(store.fd), unix.Close(store.dirFD))
}

func encodeJournalSlot(value Journal) ([]byte, error) {
	if err := validateJournal(value); err != nil {
		return nil, err
	}
	payload, err := encodeCanonical(value)
	if err != nil || len(payload) > MaximumJournalBytes {
		return nil, fmt.Errorf("bootstrap journal payload is invalid")
	}
	result := make([]byte, journalSlotBytes)
	copy(result[:8], []byte("LPBOOT01"))
	binary.BigEndian.PutUint64(result[8:16], value.Sequence)
	binary.BigEndian.PutUint32(result[16:20], uint32(len(payload)))
	copy(result[24:24+len(payload)], payload)
	binary.BigEndian.PutUint32(result[20:24], crc32.ChecksumIEEE(result[24:24+len(payload)]))
	return result, nil
}

func decodeJournalSlot(data []byte) (Journal, error) {
	if len(data) != journalSlotBytes || string(data[:8]) != "LPBOOT01" {
		return Journal{}, fmt.Errorf("bootstrap journal slot header is invalid")
	}
	sequence := binary.BigEndian.Uint64(data[8:16])
	length := binary.BigEndian.Uint32(data[16:20])
	if sequence == 0 || length == 0 || length > MaximumJournalBytes || int(24+length) > len(data) || crc32.ChecksumIEEE(data[24:24+length]) != binary.BigEndian.Uint32(data[20:24]) {
		return Journal{}, fmt.Errorf("bootstrap journal slot checksum is invalid")
	}
	var value Journal
	if err := decodeCanonical(data[24:24+length], &value); err != nil || value.Sequence != sequence {
		return Journal{}, fmt.Errorf("bootstrap journal slot payload is invalid")
	}
	if err := validateJournal(value); err != nil {
		return Journal{}, err
	}
	return value, nil
}

func journalExists(path string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Lstat(path, &stat)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

var _ io.Reader
