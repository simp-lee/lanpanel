// Package download implements bounded no-ambient-proxy artifact streaming.
package download

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"lanpanel/internal/sources"
)

type Timeouts struct {
	Connect        time.Duration
	TLSHandshake   time.Duration
	ResponseHeader time.Duration
	ReadIdle       time.Duration
	Total          time.Duration
}

type Config struct {
	Source           sources.Source
	Proxy            *sources.Proxy
	MaximumRedirects int
	Timeouts         Timeouts
}

type Request struct {
	MaximumBytes int64
	ExpectedSize int64
}

type Result struct {
	Bytes  int64
	Digest string
}

type VerifiedArtifact struct {
	Path   string
	Bytes  int64
	Digest string
}

type Downloader struct {
	config Config
	client *http.Client
}

func New(config Config) (*Downloader, error) {
	config.Source.OfficialAuthorities = append([]string(nil), config.Source.OfficialAuthorities...)
	if config.Proxy != nil {
		proxyCopy := *config.Proxy
		config.Proxy = &proxyCopy
	}
	if err := sources.Validate(config.Source); err != nil || (config.Source.Kind != sources.OfficialCanonical && config.Source.Kind != sources.Mirror) {
		return nil, fmt.Errorf("download source is not a validated network artifact")
	}
	if err := sources.ValidateProxy(config.Proxy); err != nil || config.MaximumRedirects <= 0 || config.MaximumRedirects > 10 || !validTimeouts(config.Timeouts) {
		return nil, fmt.Errorf("download proxy, redirect, or timeout policy is invalid")
	}
	var proxy func(*http.Request) (*url.URL, error)
	if config.Proxy != nil {
		parsed, _ := sources.ParseProxyURL(config.Proxy.URL)
		proxy = http.ProxyURL(parsed)
	}
	transport := &http.Transport{
		Proxy:                 proxy,
		DialContext:           (&net.Dialer{Timeout: config.Timeouts.Connect, KeepAlive: -1}).DialContext,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   config.Timeouts.TLSHandshake,
		ResponseHeaderTimeout: config.Timeouts.ResponseHeader,
		DisableKeepAlives:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	downloader := &Downloader{config: config}
	downloader.client = &http.Client{Transport: transport}
	downloader.client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return fmt.Errorf("redirect chain is missing its source")
		}
		request.Header.Del("Authorization")
		request.Header.Del("Cookie")
		request.Header.Del("Referer")
		return sources.ValidateRedirect(config.Source, via[len(via)-1].URL.String(), request.URL.String(), len(via), config.MaximumRedirects)
	}
	return downloader, nil
}

func (downloader *Downloader) FetchToStaging(ctx context.Context, request Request, staging *StagingFile) (VerifiedArtifact, error) {
	if staging == nil || staging.maximum != request.MaximumBytes {
		return VerifiedArtifact{}, fmt.Errorf("download staging does not match the request byte authority")
	}
	result, err := downloader.fetch(ctx, request, staging)
	if err != nil {
		_ = staging.Close()
		return VerifiedArtifact{}, err
	}
	path, err := staging.CloseVerified(result.Digest, result.Bytes)
	if err != nil {
		return VerifiedArtifact{}, err
	}
	return VerifiedArtifact{Path: path, Bytes: result.Bytes, Digest: result.Digest}, nil
}

func (downloader *Downloader) fetch(ctx context.Context, request Request, destination io.Writer) (Result, error) {
	if downloader == nil || downloader.client == nil || destination == nil || request.MaximumBytes <= 0 || request.ExpectedSize < 0 || request.ExpectedSize > request.MaximumBytes {
		return Result{}, fmt.Errorf("download request is invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, downloader.config.Timeouts.Total)
	defer cancel()
	var connection idleConnection
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { connection.set(info.Conn) }}
	httpRequest, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, downloader.config.Source.URL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("create artifact request")
	}
	httpRequest.Header.Set("Accept", "application/octet-stream")
	httpRequest.Header.Set("Accept-Encoding", "identity")
	response, err := downloader.client.Do(httpRequest)
	if err != nil {
		return Result{}, fmt.Errorf("download artifact: %w", redactedError(err))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" || response.ContentLength > request.MaximumBytes || request.ExpectedSize > 0 && response.ContentLength >= 0 && response.ContentLength != request.ExpectedSize {
		return Result{}, fmt.Errorf("artifact response status or declared size is invalid")
	}
	hasher := sha256.New()
	writer := io.MultiWriter(destination, hasher)
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		if err := connection.setReadDeadline(time.Now().Add(downloader.config.Timeouts.ReadIdle)); err != nil {
			return Result{}, fmt.Errorf("set artifact read-idle deadline")
		}
		read, readErr := response.Body.Read(buffer)
		if read > 0 {
			if total+int64(read) > request.MaximumBytes {
				return Result{}, fmt.Errorf("artifact response exceeds fixed byte bound")
			}
			written, writeErr := writer.Write(buffer[:read])
			if writeErr != nil || written != read {
				return Result{}, fmt.Errorf("write artifact staging stream")
			}
			total += int64(read)
		}
		if readErr != nil {
			if readErr != io.EOF {
				return Result{}, fmt.Errorf("read artifact body: %w", redactedError(readErr))
			}
			break
		}
	}
	if total == 0 || request.ExpectedSize > 0 && total != request.ExpectedSize {
		return Result{}, fmt.Errorf("artifact response is empty or truncated")
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if digest != downloader.config.Source.Artifact.Digest {
		return Result{}, fmt.Errorf("artifact digest mismatch")
	}
	return Result{Bytes: total, Digest: digest}, nil
}

func validTimeouts(timeouts Timeouts) bool {
	values := []time.Duration{timeouts.Connect, timeouts.TLSHandshake, timeouts.ResponseHeader, timeouts.ReadIdle, timeouts.Total}
	for _, value := range values {
		if value <= 0 || value > 30*time.Minute {
			return false
		}
	}
	return timeouts.Total >= timeouts.Connect && timeouts.Total >= timeouts.ResponseHeader && timeouts.Total >= timeouts.ReadIdle
}

type idleConnection struct {
	mu   sync.Mutex
	conn net.Conn
}

func (connection *idleConnection) set(value net.Conn) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.conn = value
}
func (connection *idleConnection) setReadDeadline(deadline time.Time) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.conn == nil {
		return fmt.Errorf("download connection is unavailable")
	}
	return connection.conn.SetReadDeadline(deadline)
}

type safeError string

func (err safeError) Error() string { return string(err) }

func redactedError(err error) error {
	if err == nil {
		return nil
	}
	return safeError("network operation failed")
}
