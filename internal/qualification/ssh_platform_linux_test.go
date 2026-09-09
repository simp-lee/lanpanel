//go:build linux

package qualification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"lanpanel/internal/release"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestVerifyPlatformUsesExactSystemdPackageIdentity(t *testing.T) {
	for _, layout := range []string{"regular", "alias"} {
		for _, test := range []struct {
			name, expected, observed string
			status                   uint32
			wantError                bool
		}{
			{name: "ubuntu_revision", expected: "255.4-1ubuntu8.17", observed: "255.4-1ubuntu8.17"},
			{name: "debian_revision", expected: "257.8-1~deb13u1", observed: "257.8-1~deb13u1"},
			{name: "epoch", expected: "1:257.8-1~deb13u1", observed: "1:257.8-1~deb13u1"},
			{name: "revision_drift", expected: "255.4-1ubuntu8.17", observed: "255.4-1ubuntu8.18", wantError: true},
			{name: "abbreviated_profile", expected: "255", observed: "255.4-1ubuntu8.17", wantError: true},
			{name: "empty_output", expected: "255.4-1ubuntu8.17", wantError: true},
			{name: "query_failure", expected: "255.4-1ubuntu8.17", observed: "255.4-1ubuntu8.17", status: 1, wantError: true},
		} {
			t.Run(layout+"/"+test.name, func(t *testing.T) {
				files := map[string]*qualificationSFTPFixtureFile{
					"/etc/os-release": {name: "/etc/os-release", mode: 0o644, data: []byte("ID=ubuntu\nVERSION_ID=24.04\n")},
				}
				if layout == "alias" {
					files["/usr/lib/os-release"] = files["/etc/os-release"]
					files["/etc/os-release"] = &qualificationSFTPFixtureFile{name: "/etc/os-release", mode: os.ModeSymlink | 0o777, target: "../usr/lib/os-release"}
				}
				commands := map[string]platformCommandResult{
					"/usr/bin/uname -m":          {stdout: "x86_64\n"},
					"/usr/bin/systemd --version": {stdout: "systemd 255 (255.4-1ubuntu8.17)\n"},
					"/usr/bin/dpkg-query --show --showformat='${Version}\\n' systemd": {stdout: test.observed + "\n", status: test.status},
				}
				client := openPlatformSSHFixture(t, files, commands)
				err := client.verifyPlatform(context.Background(), release.OSProfile{Family: "ubuntu", Release: "24.04", SystemdVersion: test.expected})
				if (err != nil) != test.wantError {
					t.Fatalf("verifyPlatform() = %v, wantError=%t", err, test.wantError)
				}
			})
		}
	}
}

type platformCommandResult struct {
	stdout string
	status uint32
}

func openPlatformSSHFixture(t *testing.T, files map[string]*qualificationSFTPFixtureFile, commands map[string]platformCommandResult) *SSHClient {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		server, channels, requests, handshakeErr := ssh.NewServerConn(connection, config)
		if handshakeErr != nil {
			return
		}
		defer func() { _ = server.Close() }()
		go ssh.DiscardRequests(requests)
		var sessions sync.WaitGroup
		defer sessions.Wait()
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				_ = incoming.Reject(ssh.UnknownChannelType, "session required")
				continue
			}
			channel, channelRequests, channelErr := incoming.Accept()
			if channelErr != nil {
				return
			}
			sessions.Go(func() {
				servePlatformSSHSession(channel, channelRequests, files, commands)
			})
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := OpenSSH(ctx, SSHAuthority{Address: listener.Addr().String(), User: "root", HostKeySHA256: release.DigestBytes(signer.PublicKey().Marshal()), CredentialRef: "file:" + writeTestSSHCredential(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("platform SSH fixture did not stop")
		}
	})
	return client
}

func servePlatformSSHSession(channel ssh.Channel, requests <-chan *ssh.Request, files map[string]*qualificationSFTPFixtureFile, commands map[string]platformCommandResult) {
	defer func() { _ = channel.Close() }()
	for request := range requests {
		var payload struct{ Value string }
		if ssh.Unmarshal(request.Payload, &payload) != nil {
			_ = request.Reply(false, nil)
			return
		}
		switch request.Type {
		case "subsystem":
			if payload.Value != "sftp" {
				_ = request.Reply(false, nil)
				return
			}
			_ = request.Reply(true, nil)
			fixture := &qualificationSFTPFixture{files: files}
			server := sftp.NewRequestServer(channel, sftp.Handlers{FileGet: fixture, FileList: fixture})
			_ = server.Serve()
			_ = server.Close()
			return
		case "exec":
			result, ok := commands[payload.Value]
			if !ok {
				_ = request.Reply(false, nil)
				return
			}
			_ = request.Reply(true, nil)
			_, _ = io.WriteString(channel, result.stdout)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{result.status}))
			return
		default:
			_ = request.Reply(false, nil)
		}
	}
}
