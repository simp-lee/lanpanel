//go:build linux

package qualification

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"lanpanel/internal/release"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestPinnedSSHHostKeyAndCanonicalAddress(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	digest := release.DigestBytes(key.Marshal())
	callback := pinnedHostKey(digest)
	if err := callback("ignored", &net.TCPAddr{}, key); err != nil {
		t.Fatal(err)
	}
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewPublicKey(otherPublic)
	if callback("ignored", &net.TCPAddr{}, other) == nil {
		t.Fatal("pinned SSH callback accepted another host key")
	}
	if address, err := canonicalSSHAddress("192.0.2.10:22"); err != nil || address != "192.0.2.10:22" {
		t.Fatalf("canonical SSH address rejected: %q %v", address, err)
	}
	for _, invalid := range []string{"host.example:22", "192.0.2.10", "192.0.2.10:022", "0.0.0.0:0"} {
		if _, err := canonicalSSHAddress(invalid); err == nil {
			t.Fatalf("invalid SSH address accepted: %s", invalid)
		}
	}
}

func TestOpenSSHContextStopsStalledHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		_, _ = io.Copy(io.Discard, connection)
	}()

	credential := writeTestSSHCredential(t)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_, err = OpenSSH(ctx, SSHAuthority{Address: listener.Addr().String(), User: "root", HostKeySHA256: strings.Repeat("0", 64), CredentialRef: "file:" + credential})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled SSH handshake did not return its context deadline: %v", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SSH cancellation did not close the stalled handshake connection")
	}
}

func TestOpenSSHContextStopsStalledSFTPInitialization(t *testing.T) {
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan struct{})
	go serveStalledSFTP(listener, serverConfig, serverDone)

	credential := writeTestSSHCredential(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err = OpenSSH(ctx, SSHAuthority{Address: listener.Addr().String(), User: "root", HostKeySHA256: release.DigestBytes(hostSigner.PublicKey().Marshal()), CredentialRef: "file:" + credential})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled SFTP initialization did not return its context deadline: %v", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SFTP cancellation did not close the underlying SSH connection")
	}
}

func TestSFTPReadContextStopsStalledOperation(t *testing.T) {
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan struct{})
	go serveInitializedStalledSFTP(listener, serverConfig, serverDone)

	openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
	client, err := OpenSSH(openCtx, SSHAuthority{Address: listener.Addr().String(), User: "root", HostKeySHA256: release.DigestBytes(hostSigner.PublicKey().Marshal()), CredentialRef: "file:" + writeTestSSHCredential(t)})
	openCancel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	operationCtx, operationCancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer operationCancel()
	_, err = client.sftpLstat(operationCtx, "/stalled")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled SFTP read did not return its context deadline: %v", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SFTP operation cancellation did not close the underlying connection")
	}
}

func TestSSHTunnelDialContextStopsStalledChannelOpen(t *testing.T) {
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan struct{})
	go serveInitializedStalledTunnel(listener, serverConfig, serverDone)

	openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
	client, err := OpenSSH(openCtx, SSHAuthority{Address: listener.Addr().String(), User: "root", HostKeySHA256: release.DigestBytes(hostSigner.PublicKey().Marshal()), CredentialRef: "file:" + writeTestSSHCredential(t)})
	openCancel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer dialCancel()
	connection, err := client.dialContext(dialCtx, "tcp", "127.0.0.1:52345")
	if connection != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled SSH tunnel returned connection=%v err=%v", connection, err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SSH tunnel cancellation did not close the underlying connection")
	}
}

func TestDERPExchangeContextStopsStalledWrite(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer func() { _ = serverConnection.Close() }()
	request, err := http.NewRequest(http.MethodGet, "https://control.example.com/derp", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_, err = exchangeDERPUpgrade(ctx, clientConnection, request)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled DERP request write did not return its context deadline: %v", err)
	}
}

func TestDERPExchangeContextStopsStalledResponse(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer func() { _ = serverConnection.Close() }()
		_, _ = http.ReadRequest(bufio.NewReader(serverConnection))
		_, _ = io.Copy(io.Discard, serverConnection)
	}()
	request, err := http.NewRequest(http.MethodGet, "https://control.example.com/derp", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_, err = exchangeDERPUpgrade(ctx, clientConnection, request)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled DERP response did not return its context deadline: %v", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("DERP cancellation did not close the stalled connection")
	}
}

func writeTestSSHCredential(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func serveInitializedStalledTunnel(listener net.Listener, config *ssh.ServerConfig, done chan<- struct{}) {
	defer close(done)
	connection, err := listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = connection.Close() }()
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	defer func() { _ = server.Close() }()
	go ssh.DiscardRequests(requests)
	connectionDone := make(chan struct{})
	go func() {
		_ = server.Wait()
		close(connectionDone)
	}()
	for request := range channels {
		switch request.ChannelType() {
		case "session":
			channel, channelRequests, acceptErr := request.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = channel.Close() }()
				subsystem, present := <-channelRequests
				if !present || subsystem.Type != "subsystem" {
					return
				}
				_ = subsystem.Reply(true, nil)
				packet, readErr := readTestSFTPPacket(channel)
				if readErr != nil || len(packet) != 5 || packet[0] != 1 {
					return
				}
				_, _ = channel.Write([]byte{0, 0, 0, 5, 2, 0, 0, 0, 3})
				<-connectionDone
			}()
		case "direct-tcpip":
			// Leave the channel-open request unanswered until caller cancellation
			// closes the transport.
			<-connectionDone
			return
		default:
			_ = request.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func serveInitializedStalledSFTP(listener net.Listener, config *ssh.ServerConfig, done chan<- struct{}) {
	defer close(done)
	connection, err := listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = connection.Close() }()
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	defer func() { _ = server.Close() }()
	go ssh.DiscardRequests(requests)
	channelRequest, present := <-channels
	if !present || channelRequest.ChannelType() != "session" {
		return
	}
	channel, channelRequests, err := channelRequest.Accept()
	if err != nil {
		return
	}
	defer func() { _ = channel.Close() }()
	request, present := <-channelRequests
	if !present || request.Type != "subsystem" {
		return
	}
	_ = request.Reply(true, nil)
	packet, err := readTestSFTPPacket(channel)
	if err != nil || len(packet) != 5 || packet[0] != 1 {
		return
	}
	version := []byte{0, 0, 0, 5, 2, 0, 0, 0, 3}
	if _, err := channel.Write(version); err != nil {
		return
	}
	if _, err := readTestSFTPPacket(channel); err != nil {
		return
	}
	_ = server.Wait()
}

func readTestSFTPPacket(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > 1<<20 {
		return nil, errors.New("invalid test SFTP packet")
	}
	packet := make([]byte, length)
	_, err := io.ReadFull(reader, packet)
	return packet, err
}

func serveStalledSFTP(listener net.Listener, config *ssh.ServerConfig, done chan<- struct{}) {
	defer close(done)
	connection, err := listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = connection.Close() }()
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	defer func() { _ = server.Close() }()
	go ssh.DiscardRequests(requests)
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		channel, channelRequests, acceptErr := channelRequest.Accept()
		if acceptErr != nil {
			return
		}
		go func() {
			defer func() { _ = channel.Close() }()
			for request := range channelRequests {
				_ = request.Reply(request.Type == "subsystem", nil)
			}
		}()
	}
}
