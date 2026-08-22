//go:build linux

package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/bootstrap"
	"lanpanel/internal/release"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

type ManagementClient struct {
	ssh    *SSHClient
	http   *http.Client
	origin string
	proof  string
	csrf   string
}

func OpenManagementClient(ctx context.Context, target *SSHClient) (*ManagementClient, error) {
	startupBytes, err := target.readRemoteRegular("/etc/lanpanel/startup-authority.json", 4<<20)
	if err != nil {
		return nil, err
	}
	var startup bootstrap.StartupAuthority
	if err := release.DecodeCanonical(startupBytes, &startup); err != nil {
		return nil, err
	}
	address := net.JoinHostPort(startup.Management.Address, strconv.Itoa(int(startup.Management.Port)))
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" || requested != address {
				return nil, fmt.Errorf("management tunnel destination escaped exact authority")
			}
			type result struct {
				connection net.Conn
				err        error
			}
			done := make(chan result, 1)
			go func() { connection, dialErr := target.client.Dial("tcp", address); done <- result{connection, dialErr} }()
			select {
			case value := <-done:
				return value.connection, value.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		DisableKeepAlives: false, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		ResponseHeaderTimeout: 0, ExpectContinueTimeout: time.Second,
	}
	client := &ManagementClient{ssh: target, http: &http.Client{Transport: transport, Jar: jar, Timeout: 0, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, origin: "http://" + address}
	if err := client.login(ctx); err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	return client, nil
}

func (client *ManagementClient) Close() {
	if client != nil && client.http != nil {
		if transport, ok := client.http.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
}

func (client *ManagementClient) login(ctx context.Context) error {
	token, err := client.ssh.readRemoteRegular("/var/lib/lanpanel/installation/admin-token", 4096)
	if err != nil {
		return err
	}
	form := url.Values{"token": []string{string(token)}}.Encode()
	clearBytes(token)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.origin+"/login", strings.NewReader(form))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", client.origin)
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	data, readErr := readHTTPResponse(response, 1<<20)
	if readErr != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("management login failed with status %d: %w", response.StatusCode, readErr)
	}
	var credentials struct {
		Proof string `json:"proof"`
		CSRF  string `json:"csrf"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil || decoder.Decode(&struct{}{}) != io.EOF || credentials.Proof == "" || credentials.CSRF == "" {
		return fmt.Errorf("management login response is invalid: %w", err)
	}
	client.proof, client.csrf = credentials.Proof, credentials.CSRF
	var session struct {
		Profile string `json:"profile"`
	}
	if _, err := client.request(ctx, http.MethodGet, "/api/session", nil, &session, false); err != nil || session.Profile != "normal" {
		return fmt.Errorf("management normal session is unavailable: %w", err)
	}
	return nil
}

func (client *ManagementClient) Post(ctx context.Context, path string, body any, result any) ([]byte, error) {
	return client.request(ctx, http.MethodPost, path, body, result, true)
}

func (client *ManagementClient) Get(ctx context.Context, path string, result any) ([]byte, error) {
	return client.request(ctx, http.MethodGet, path, nil, result, false)
}

func (client *ManagementClient) request(ctx context.Context, method, path string, body any, result any, mutation bool) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\r\n") || len(path) > 2048 {
		return nil, fmt.Errorf("management path is invalid")
	}
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, client.origin+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-LanPanel-Session-Proof", client.proof)
	if mutation {
		request.Header.Set("X-LanPanel-CSRF", client.csrf)
		request.Header.Set("Origin", client.origin)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, err
	}
	data, readErr := readHTTPResponse(response, 4<<20)
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("management %s %s failed with status %d and digest %s", method, path, response.StatusCode, release.DigestBytes(data))
	}
	trimmed := bytes.TrimSpace(data)
	if result != nil {
		if len(trimmed) == 0 {
			return nil, fmt.Errorf("management response is empty")
		}
		if err := json.Unmarshal(trimmed, result); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (client *ManagementClient) Plan(ctx context.Context, path, query string, body any) (string, error) {
	if body == nil {
		body = struct{}{}
	}
	var plan struct {
		PlanID string `json:"plan_id"`
	}
	if _, err := client.Post(ctx, path+"/plan"+query, body, &plan); err != nil || plan.PlanID == "" {
		return "", fmt.Errorf("management Plan failed: %w", err)
	}
	return plan.PlanID, nil
}

func (client *ManagementClient) PlanAndExecute(ctx context.Context, path, query, confirmation string, planBody, executeBody map[string]any, result any) ([]byte, error) {
	if planBody == nil {
		planBody = map[string]any{}
	}
	var plan struct {
		PlanID string `json:"plan_id"`
	}
	if _, err := client.Post(ctx, path+"/plan"+query, planBody, &plan); err != nil || plan.PlanID == "" {
		return nil, fmt.Errorf("management Plan failed: %w", err)
	}
	if executeBody == nil {
		executeBody = map[string]any{}
	}
	executeBody["plan_id"] = plan.PlanID
	executeBody["confirmation"] = confirmation
	return client.Post(ctx, path+query, executeBody, result)
}

func (client *ManagementClient) VerifyWebSocket(ctx context.Context) error {
	header := http.Header{}
	header.Set("Origin", client.origin)
	connection, response, err := websocket.Dial(ctx, client.origin+"/api/events", &websocket.DialOptions{HTTPClient: client.http, HTTPHeader: header, Subprotocols: []string{"lanpanel.events.v1"}})
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
		}
		return err
	}
	defer func() { _ = connection.Close(websocket.StatusNormalClosure, "complete") }()
	message, _ := json.Marshal(struct {
		Type  string `json:"type"`
		Proof string `json:"proof"`
	}{"auth", client.proof})
	if err := connection.Write(ctx, websocket.MessageText, message); err != nil {
		return err
	}
	_, responseBytes, err := connection.Read(ctx)
	if err != nil || len(responseBytes) == 0 || len(responseBytes) > 1<<20 {
		return fmt.Errorf("management WebSocket authentication did not return a bounded event: %w", err)
	}
	return nil
}

func readHTTPResponse(response *http.Response, maximum int64) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("HTTP response is missing")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, fmt.Errorf("HTTP response is unreadable or unbounded: %w", err)
	}
	return data, nil
}
