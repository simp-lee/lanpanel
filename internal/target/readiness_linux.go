//go:build linux

package target

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type UnixTransport struct {
	path, identity string
	uid, gid       uint32
	mode           uint32
}

func NewUnixTransport(path, identity string, uid, gid uint32, mode uint32) (UnixTransport, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || identity == "" || uid != 0 || gid == 0 || mode != 0o660 {
		return UnixTransport{}, fmt.Errorf("unix readiness endpoint authority is invalid")
	}
	return UnixTransport{path: path, identity: identity + "/unix", uid: uid, gid: gid, mode: mode}, nil
}
func (transport UnixTransport) Identity() string { return transport.identity }
func (transport UnixTransport) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	var before unix.Stat_t
	if err := unix.Lstat(transport.path, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Uid != transport.uid || before.Gid != transport.gid || before.Mode&0o777 != transport.mode {
		return nil, fmt.Errorf("unix readiness endpoint ownership changed")
	}
	connection, err := (&net.Dialer{Timeout: ConnectTimeout}).DialContext(ctx, "unix", transport.path)
	if err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if err := unix.Lstat(transport.path, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Ctim != after.Ctim {
		_ = connection.Close()
		return nil, fmt.Errorf("unix readiness endpoint changed during connect")
	}
	return connection, nil
}

var _ = os.ErrNotExist
