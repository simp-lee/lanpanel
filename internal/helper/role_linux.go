//go:build linux

package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lanpanel/internal/helperproto"
	"lanpanel/internal/packages"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const FixedIdentityConfigPath = "/var/lib/lanpanel/installation/helper-identities.json"
const identityConfigSchema = "lanpanel.helper.identities.v1"
const maximumIdentityConfigBytes = 4096

type identityConfig struct {
	SchemaVersion string      `json:"schema_version"`
	SocketGroup   uint32      `json:"socket_group"`
	Identities    IdentitySet `json:"identities"`
}

// RunRole starts the fixed root helper role. Component operations remain
// unavailable until their owning package registers a complete typed handler.
func RunRole(args []string) error {
	if len(args) != 0 || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("helper role requires its fixed root service invocation")
	}
	config, err := readIdentityConfig()
	if err != nil {
		return err
	}
	packageService, err := packages.OpenFixedService()
	if err != nil {
		return fmt.Errorf("open fixed package transaction service: %w", err)
	}
	defer packageService.Close()
	packageHandler := PackageTransactionHandler(
		func(ctx context.Context, caller helperproto.Caller, request helperproto.Request) error {
			if caller != helperproto.CallerUI {
				return fmt.Errorf("package transaction caller is unauthorized")
			}
			return packageService.ValidateRequest(ctx, request)
		},
		func(ctx context.Context, caller helperproto.Caller, request helperproto.Request, secret *helperproto.Secret) (ExecutionResult, error) {
			if caller != helperproto.CallerUI || secret != nil {
				return ExecutionResult{}, fmt.Errorf("package transaction execution authority is invalid")
			}
			digest, err := packageService.Execute(ctx, request)
			return ExecutionResult{ResultDigest: digest}, err
		},
	)
	server, err := NewServer(config.Identities, []Registration{packageHandler}, Options{})
	if err != nil {
		return err
	}
	listener, err := ListenProtected(config.SocketGroup)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return server.Serve(ctx, listener)
}

func readIdentityConfig() (identityConfig, error) {
	parent := filepath.Dir(FixedIdentityConfigPath)
	if err := validateRootParentChain(parent, 0, 0o700); err != nil {
		return identityConfig{}, fmt.Errorf("helper identity parent chain: %w", err)
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return identityConfig{}, fmt.Errorf("open helper identity parent: %w", err)
	}
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil || parentStat.Uid != 0 || parentStat.Gid != 0 || parentStat.Mode&0o777 != 0o700 {
		return identityConfig{}, fmt.Errorf("helper identity parent is not root-owned mode 0700")
	}
	fd, err := unix.Openat(parentFD, filepath.Base(FixedIdentityConfigPath), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return identityConfig{}, fmt.Errorf("open helper identity config: %w", err)
	}
	file := os.NewFile(uintptr(fd), "helper-identities")
	if file == nil {
		_ = unix.Close(fd)
		return identityConfig{}, fmt.Errorf("helper identity descriptor is invalid")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o600 || stat.Size <= 0 || stat.Size > maximumIdentityConfigBytes {
		return identityConfig{}, fmt.Errorf("helper identity config ownership, type, mode, link, or size is invalid")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximumIdentityConfigBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumIdentityConfigBytes {
		return identityConfig{}, fmt.Errorf("read bounded helper identity config")
	}
	var config identityConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return identityConfig{}, fmt.Errorf("decode helper identity config")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return identityConfig{}, fmt.Errorf("helper identity config has trailing data")
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, payload) || config.SchemaVersion != identityConfigSchema || config.SocketGroup == 0 {
		return identityConfig{}, fmt.Errorf("helper identity config is noncanonical or incomplete")
	}
	if err := validateIdentities(config.Identities); err != nil {
		return identityConfig{}, err
	}
	return config, nil
}
