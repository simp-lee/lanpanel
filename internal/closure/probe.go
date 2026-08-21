package closure

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type NegativeProbe struct {
	TLSAddress             string
	DefaultCertFingerprint string
	AuditPath              string
	TargetObserved         func(context.Context, Inventory, string, string) (bool, error)
	Dialer                 func(context.Context, string, string) (net.Conn, error)
	Now                    func() time.Time
}

func (probe NegativeProbe) Run(ctx context.Context, inventory Inventory) (string, error) {
	if !inventory.Complete || probe.TLSAddress == "" || !validDigest(probe.DefaultCertFingerprint) || probe.AuditPath == "" {
		return "", fmt.Errorf("negative closure probe authority is incomplete")
	}
	if probe.Now == nil {
		probe.Now = func() time.Time { return time.Now().UTC() }
	}
	if probe.Dialer == nil {
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		probe.Dialer = dialer.DialContext
	}
	correlationSource := sha256.Sum256([]byte(inventory.Digest + "\x00" + probe.Now().UTC().Format(time.RFC3339Nano)))
	correlation := "close-" + hex.EncodeToString(correlationSource[:16])
	domains := []string{}
	listeners := []string{}
	for _, identity := range inventory.Identities {
		switch identity.Kind {
		case IdentityDomain:
			domains = append(domains, identity.Value)
		case IdentityTemporaryListener:
			listeners = append(listeners, identity.Value)
		}
	}
	for _, domain := range domains {
		if err := probeDomain(ctx, probe, domain, domain, correlation); err != nil {
			return "", err
		}
		if err := probeDomain(ctx, probe, domain, "mismatch.invalid", correlation); err != nil {
			return "", err
		}
	}
	if len(domains) != 0 {
		if err := probeDomain(ctx, probe, "unmatched.invalid", "unmatched.invalid", correlation); err != nil {
			return "", err
		}
	}
	for _, listener := range listeners {
		protocol, address, portText, found := cutListener(listener)
		port, err := strconv.ParseUint(portText, 10, 16)
		if !found || protocol != "tcp" || address != "0.0.0.0" || err != nil {
			return "", fmt.Errorf("temporary closure listener identity is invalid")
		}
		connection, dialErr := probe.Dialer(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		if dialErr == nil {
			_ = connection.Close()
			return "", fmt.Errorf("owned temporary listener still accepts connections")
		}
		var operationError *net.OpError
		if !errors.As(dialErr, &operationError) || !errors.Is(operationError.Err, syscall.ECONNREFUSED) {
			return "", fmt.Errorf("temporary listener refusal was not exact")
		}
	}
	if len(domains) != 0 {
		if probe.TargetObserved == nil {
			return "", fmt.Errorf("target correlation observer is unavailable")
		}
		for _, domainName := range domains {
			observed, err := probe.TargetObserved(ctx, inventory, domainName, correlation)
			if err != nil || observed {
				return "", fmt.Errorf("target observed closure correlation")
			}
		}
		data, err := os.ReadFile(probe.AuditPath)
		if err != nil || !strings.Contains(string(data), correlation) {
			return "", fmt.Errorf("release-owned rejection audit lacks correlation")
		}
	}
	digest := sha256.Sum256([]byte(inventory.Digest + "\x00" + correlation))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func probeDomain(ctx context.Context, probe NegativeProbe, sni, host, correlation string) error {
	raw, err := probe.Dialer(ctx, "tcp", probe.TLSAddress)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(raw.Close)
	connection := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := connection.HandshakeContext(ctx); err != nil {
		return err
	}
	certificate := connection.ConnectionState().PeerCertificates[0]
	fingerprint := sha256.Sum256(certificate.Raw)
	if "sha256:"+hex.EncodeToString(fingerprint[:]) != probe.DefaultCertFingerprint {
		return fmt.Errorf("closure probe reached a non-default certificate")
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/__lanpanel_closed", nil)
	request.Host = host
	request.Header.Set("X-LanPanel-Closure-ID", correlation)
	if err := request.Write(connection); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return err
	}
	defer func(ignore func() error) { _ = ignore() }(response.Body.Close)
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if readErr != nil || response.StatusCode != http.StatusMisdirectedRequest || response.Header.Get("X-LanPanel-Rejection") != "default" {
		return fmt.Errorf("closure probe did not hit fixed default rejection")
	}
	return nil
}

func cutListener(value string) (string, string, string, bool) {
	protocol, rest, found := strings.Cut(value, ":")
	if !found {
		return "", "", "", false
	}
	address, port, found := strings.Cut(rest, ":")
	return protocol, address, port, found
}
