//go:build linux

// Package helper implements the root-only, peer-authenticated typed helper.
package helper

import (
	"context"
	"errors"
	"fmt"
	"lanpanel/internal/helperproto"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const FixedSocketPath = "/run/lanpanel/helper.sock"

type PeerIdentity struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type IdentitySet struct {
	UI       PeerIdentity `json:"ui"`
	Timer    PeerIdentity `json:"timer"`
	Recovery PeerIdentity `json:"recovery"`
}

type Revalidator func(context.Context, helperproto.Caller, helperproto.Request) error
type ExecutionResult struct {
	ResultDigest string
	Secret       *helperproto.Secret
	Action       *helperproto.ActionResult
	Resource     *helperproto.ResourceResult
}

type Executor func(context.Context, helperproto.Caller, helperproto.Request, *helperproto.Secret) (ExecutionResult, error)

type handler struct {
	revalidate Revalidator
	execute    Executor
}

type Registration struct {
	operation helperproto.Operation
	handler   handler
}

func newRegistration(operation helperproto.Operation, revalidate Revalidator, execute Executor) Registration {
	return Registration{operation: operation, handler: handler{revalidate: revalidate, execute: execute}}
}

func ApplicationPlanHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationApplicationPlan, r, e)
}
func ManagedFileCommitHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationManagedFileCommit, r, e)
}
func AccountCreateHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationAccountCreate, r, e)
}
func AdminTokenVerifyHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationAdminTokenVerify, r, e)
}
func AdminTokenSourceHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationAdminTokenSource, r, e)
}
func ManagementProfileHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationManagementProfile, r, e)
}
func AdminTokenRotateHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationAdminTokenRotate, r, e)
}
func AdminTokenReconcileHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationAdminTokenReconcile, r, e)
}
func PackageTransactionHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationPackageTransaction, r, e)
}
func SystemdTransitionHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationSystemdTransition, r, e)
}
func NginxTestHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationNginxTest, r, e)
}
func NginxReloadHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationNginxReload, r, e)
}
func CredentialImportHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationCredentialImport, r, e)
}
func CredentialAdoptHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationCredentialAdopt, r, e)
}
func CertificateIssueHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationCertificateIssue, r, e)
}
func CertificateRenewHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationCertificateRenew, r, e)
}
func EdgeOneRefreshHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationEdgeOneRefresh, r, e)
}
func HeadscaleAdminHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationHeadscaleAdmin, r, e)
}
func PreauthKeyCreateHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationPreauthKeyCreate, r, e)
}
func TailscaleAuthImportHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationTailscaleAuthImport, r, e)
}
func TailscaleAuthAdoptHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationTailscaleAuthAdopt, r, e)
}
func TailscaleAdminHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationTailscaleAdmin, r, e)
}
func GoAccessProbeHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationGoAccessProbe, r, e)
}
func ManagedBasicGenerateHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationManagedBasicGenerate, r, e)
}
func ManagedBasicDeleteHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationManagedBasicDelete, r, e)
}
func StaticRootRegisterHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationStaticRootRegister, r, e)
}
func ExternalHTPasswdRegisterHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationExternalHTPasswdRegister, r, e)
}
func DomainStatusHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationDomainStatus, r, e)
}
func ContractionCloseHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationContractionClose, r, e)
}
func StartupContractionHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationStartupContraction, r, e)
}
func ResourceMutationHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationResourceMutation, r, e)
}
func ProcessLifecycleHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationProcessLifecycle, r, e)
}
func PublicationActivateHandler(r Revalidator, e Executor) Registration {
	return newRegistration(helperproto.OperationPublicationActivate, r, e)
}

type Server struct {
	identities IdentitySet
	handlers   map[helperproto.Operation]handler
	now        func() time.Time
	ioTimeout  time.Duration
}

type Options struct {
	Now       func() time.Time
	IOTimeout time.Duration
}

func NewServer(identities IdentitySet, registrations []Registration, options Options) (*Server, error) {
	if err := validateIdentities(identities); err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	timeout := options.IOTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if timeout < time.Second || timeout > 30*time.Second {
		return nil, fmt.Errorf("helper protocol timeout is outside the fixed bound")
	}
	server := &Server{identities: identities, handlers: map[helperproto.Operation]handler{}, now: now, ioTimeout: timeout}
	for _, registration := range registrations {
		if _, known := helperproto.PolicyFor(registration.operation); !known || registration.handler.revalidate == nil || registration.handler.execute == nil {
			return nil, fmt.Errorf("helper handler registration is unknown or incomplete")
		}
		if _, duplicate := server.handlers[registration.operation]; duplicate {
			return nil, fmt.Errorf("helper operation is registered twice")
		}
		server.handlers[registration.operation] = registration.handler
	}
	return server, nil
}

func validateIdentities(identities IdentitySet) error {
	values := []PeerIdentity{identities.UI, identities.Timer, identities.Recovery}
	seenUID := map[uint32]bool{}
	for _, identity := range values {
		if identity.UID == 0 || identity.GID == 0 || seenUID[identity.UID] {
			return fmt.Errorf("helper peer identities must have distinct dedicated non-root UIDs")
		}
		seenUID[identity.UID] = true
	}
	return nil
}

func (server *Server) Serve(ctx context.Context, protected *ProtectedListener) error {
	if server == nil || os.Geteuid() != 0 || protected == nil || protected.listener == nil || protected.path != FixedSocketPath {
		return fmt.Errorf("helper server or protected listener is nil")
	}
	return server.serveUnix(ctx, protected.listener, true)
}

func (server *Server) serveUnix(ctx context.Context, listener *net.UnixListener, requireRoot bool) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		if err := listener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if netError, ok := err.(net.Error); ok && netError.Timeout() {
				continue
			}
			return err
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer connection.Close()
			_ = server.serveConnection(ctx, connection, requireRoot)
		}()
	}
}

func (server *Server) serveConnection(ctx context.Context, connection *net.UnixConn, requireRoot bool) error {
	credential, err := peerCredential(connection)
	if err != nil {
		return err
	}
	caller, ok := server.callerFor(credential)
	if !ok {
		return fmt.Errorf("helper peer is unauthorized")
	}
	for {
		deadline := time.Now().Add(server.ioTimeout)
		if err := connection.SetDeadline(deadline); err != nil {
			return err
		}
		request, secret, err := helperproto.ReadRequest(connection)
		if err != nil {
			return err
		}
		destroySecret := func() {
			if secret != nil {
				secret.Destroy()
			}
		}
		now := server.now().UTC()
		if err := helperproto.ValidateRequest(request, now); err != nil || !helperproto.Authorized(caller, request.Operation) {
			destroySecret()
			return server.writeFailure(connection, request.Operation, request.RequestID, "request_rejected")
		}
		remaining := request.Deadline.Sub(now)
		if err := connection.SetDeadline(time.Now().Add(remaining)); err != nil {
			destroySecret()
			return err
		}
		requestContext, cancel := context.WithTimeout(ctx, remaining)
		go func() { buffer := make([]byte, 1); _, _ = connection.Read(buffer); cancel() }()
		handler, available := server.handlers[request.Operation]
		if !available {
			cancel()
			destroySecret()
			return server.writeFailure(connection, request.Operation, request.RequestID, "operation_unavailable")
		}
		if requireRoot && (os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0) {
			cancel()
			destroySecret()
			return server.writeFailure(connection, request.Operation, request.RequestID, "helper_privilege_missing")
		}
		if err := handler.revalidate(requestContext, caller, request); err != nil {
			cancel()
			destroySecret()
			return server.writeFailure(connection, request.Operation, request.RequestID, "authority_rejected")
		}
		if requireRoot && (os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0) {
			cancel()
			destroySecret()
			return server.writeFailure(connection, request.Operation, request.RequestID, "helper_privilege_missing")
		}
		result, err := handler.execute(requestContext, caller, request, secret)
		cancel()
		destroySecret()
		terminalPartial := request.Operation == helperproto.OperationPublicationActivate && result.Secret == nil && result.Action != nil && result.Action.JobResult == "partial" && result.Action.JobID != "" && result.Action.PublicURL != "" && result.ResultDigest != ""
		if err != nil && !terminalPartial {
			if result.Secret != nil {
				result.Secret.Destroy()
			}
			return server.writeFailure(connection, request.Operation, request.RequestID, "execution_failed")
		}
		response := helperproto.Response{SchemaVersion: helperproto.SchemaVersion, RequestID: request.RequestID, Code: helperproto.ResponseSucceeded, ResultDigest: result.ResultDigest, Action: result.Action, Resource: result.Resource}
		return helperproto.WriteResponse(connection, request.Operation, response, result.Secret)
	}
}

func (server *Server) writeFailure(connection *net.UnixConn, operation helperproto.Operation, requestID, code string) error {
	response := helperproto.Response{SchemaVersion: helperproto.SchemaVersion, RequestID: requestID, Code: helperproto.ResponseRejected, ErrorCode: code}
	return helperproto.WriteResponse(connection, operation, response, nil)
}

func (server *Server) callerFor(credential unix.Ucred) (helperproto.Caller, bool) {
	identity := PeerIdentity{UID: credential.Uid, GID: credential.Gid}
	switch identity {
	case server.identities.UI:
		return helperproto.CallerUI, true
	case server.identities.Timer:
		return helperproto.CallerTimer, true
	case server.identities.Recovery:
		return helperproto.CallerRecovery, true
	default:
		return "", false
	}
}

func peerCredential(connection *net.UnixConn) (unix.Ucred, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return unix.Ucred{}, err
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return unix.Ucred{}, err
	}
	if socketErr != nil || credential == nil || credential.Pid <= 1 {
		return unix.Ucred{}, fmt.Errorf("read helper peer credential: %w", socketErr)
	}
	return *credential, nil
}

type ProtectedListener struct {
	listener *net.UnixListener
	path     string
	device   uint64
	inode    uint64
}

func ListenProtected(socketGroup uint32) (*ProtectedListener, error) {
	path := FixedSocketPath
	if os.Geteuid() != 0 || socketGroup == 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("helper socket requires root, its fixed path, and a dedicated client group")
	}
	parent := filepath.Dir(path)
	if err := validateRootParentChain(parent, socketGroup, 0o710); err != nil {
		return nil, fmt.Errorf("helper socket parent is unsafe: %w", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("helper socket path already exists")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	fail := func(err error) (*ProtectedListener, error) {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return fail(err)
	}
	if err := os.Chown(path, 0, int(socketGroup)); err != nil {
		return fail(err)
	}
	var stat syscall.Stat_t
	if err := syscall.Lstat(path, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK || stat.Uid != 0 || stat.Gid != socketGroup || stat.Mode&0o777 != 0o660 {
		return fail(fmt.Errorf("helper socket identity verification failed"))
	}
	return &ProtectedListener{listener: listener, path: path, device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func validateRootParentChain(path string, finalGID uint32, finalMode uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("parent path is not absolute and clean")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for index, component := range components {
		current = filepath.Join(current, component)
		var stat syscall.Stat_t
		if err := syscall.Lstat(current, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			return fmt.Errorf("parent component is linked, non-directory, non-root-owned, or writable")
		}
		if index == len(components)-1 && (stat.Gid != finalGID || stat.Mode&0o777 != finalMode) {
			return fmt.Errorf("final parent group or mode is invalid")
		}
	}
	return nil
}

func (listener *ProtectedListener) UnixListener() *net.UnixListener {
	if listener == nil {
		return nil
	}
	return listener.listener
}

func (listener *ProtectedListener) Close() error {
	if listener == nil || listener.listener == nil {
		return fmt.Errorf("helper listener is not active")
	}
	closeErr := listener.listener.Close()
	listener.listener = nil
	var stat syscall.Stat_t
	if err := syscall.Lstat(listener.path, &stat); err != nil {
		return errors.Join(closeErr, err)
	}
	if uint64(stat.Dev) != listener.device || stat.Ino != listener.inode || stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return errors.Join(closeErr, fmt.Errorf("helper socket identity changed before cleanup"))
	}
	return errors.Join(closeErr, os.Remove(listener.path))
}
