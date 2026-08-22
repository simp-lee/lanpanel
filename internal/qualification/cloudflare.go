package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const cloudflareAPI = "https://api.cloudflare.com/client/v4"

type cloudflareClient struct {
	token []byte
	http  *http.Client
	zone  string
}

type cloudflareRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

type cloudflareEnvelope struct {
	Success    bool              `json:"success"`
	Errors     []json.RawMessage `json:"errors"`
	Messages   []json.RawMessage `json:"messages"`
	Result     json.RawMessage   `json:"result"`
	ResultInfo json.RawMessage   `json:"result_info,omitempty"`
}

func openCloudflare(authority DNSAuthority) (*cloudflareClient, error) {
	if authority.Provider != "cloudflare" || !strings.HasPrefix(authority.CredentialRef, "file:") {
		return nil, fmt.Errorf("first live DNS executor requires a protected cloudflare token file")
	}
	token, _, err := readProtectedFile(strings.TrimPrefix(authority.CredentialRef, "file:"), 16<<10, false)
	if err != nil {
		return nil, err
	}
	if len(token) < 20 || len(token) > 4096 || bytes.ContainsAny(token, "\x00\r\n ") {
		clearBytes(token)
		return nil, fmt.Errorf("cloudflare token shape is invalid")
	}
	client := &cloudflareClient{token: token, http: &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second}, Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	query := url.Values{"name": []string{authority.BaseDomain}, "status": []string{"active"}, "per_page": []string{"2"}}
	if err := client.do(context.Background(), http.MethodGet, "/zones?"+query.Encode(), nil, &zones); err != nil || len(zones) != 1 || zones[0].Name != authority.BaseDomain || zones[0].ID == "" {
		client.Close()
		return nil, fmt.Errorf("cloudflare token does not resolve exactly one authorized zone: %w", err)
	}
	client.zone = zones[0].ID
	return client, nil
}

func (client *cloudflareClient) Close() {
	if client == nil {
		return
	}
	clearBytes(client.token)
	if transport, ok := client.http.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (client *cloudflareClient) CreateA(ctx context.Context, name, address string) (cloudflareRecord, error) {
	if !canonicalDomain(name) || client.zone == "" {
		return cloudflareRecord{}, fmt.Errorf("cloudflare record selector is invalid")
	}
	for _, kind := range []string{"A", "AAAA", "CNAME"} {
		records, err := client.List(ctx, name, kind)
		if err != nil {
			return cloudflareRecord{}, err
		}
		if len(records) != 0 {
			return cloudflareRecord{}, fmt.Errorf("cloudflare record prior state is not empty for %s %s", kind, name)
		}
	}
	request := struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
	}{"A", name, address, 1, false}
	var record cloudflareRecord
	if err := client.do(ctx, http.MethodPost, "/zones/"+client.zone+"/dns_records", request, &record); err != nil {
		return cloudflareRecord{}, err
	}
	if record.ID == "" || record.Type != "A" || record.Name != name || record.Content != address || record.Proxied {
		return cloudflareRecord{}, fmt.Errorf("cloudflare created record identity differs")
	}
	return record, nil
}

func (client *cloudflareClient) List(ctx context.Context, name, kind string) ([]cloudflareRecord, error) {
	if !canonicalDomain(name) || !containsString([]string{"A", "AAAA", "CNAME", "TXT"}, kind) {
		return nil, fmt.Errorf("cloudflare record query is invalid")
	}
	query := url.Values{"name": []string{name}, "type": []string{kind}, "per_page": []string{"100"}}
	var records []cloudflareRecord
	if err := client.do(ctx, http.MethodGet, "/zones/"+client.zone+"/dns_records?"+query.Encode(), nil, &records); err != nil {
		return nil, err
	}
	if len(records) > 100 {
		return nil, fmt.Errorf("cloudflare record inventory is unbounded")
	}
	for _, record := range records {
		if record.ID == "" || record.Name != name || record.Type != kind {
			return nil, fmt.Errorf("cloudflare record query returned foreign identity")
		}
	}
	return records, nil
}

func (client *cloudflareClient) DeleteExact(ctx context.Context, record cloudflareRecord) error {
	if record.ID == "" || record.Name == "" || record.Type == "" {
		return fmt.Errorf("cloudflare cleanup identity is incomplete")
	}
	var deleted struct {
		ID string `json:"id"`
	}
	if err := client.do(ctx, http.MethodDelete, "/zones/"+client.zone+"/dns_records/"+record.ID, nil, &deleted); err != nil {
		records, listErr := client.List(ctx, record.Name, record.Type)
		if listErr != nil {
			return errors.Join(err, listErr)
		}
		for _, current := range records {
			if current.ID == record.ID {
				return err
			}
		}
		return nil
	}
	if deleted.ID != record.ID {
		return fmt.Errorf("cloudflare cleanup deleted a different record")
	}
	records, err := client.List(ctx, record.Name, record.Type)
	if err != nil {
		return err
	}
	for _, current := range records {
		if current.ID == record.ID {
			return fmt.Errorf("cloudflare exact record remains after cleanup")
		}
	}
	return nil
}

func (client *cloudflareClient) RequireNoTXT(ctx context.Context, owner string) error {
	records, err := client.List(ctx, owner, "TXT")
	if err != nil {
		return err
	}
	if len(records) != 0 {
		return fmt.Errorf("cloudflare TXT cleanup is incomplete or ambiguous")
	}
	return nil
}

func (client *cloudflareClient) do(ctx context.Context, method, path string, body any, output any) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("cloudflare API path is invalid")
	}
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, cloudflareAPI+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+string(client.token))
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	data, readErr := readHTTPResponse(response, 4<<20)
	if readErr != nil || response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("cloudflare API request failed with status %d: %w", response.StatusCode, readErr)
	}
	var envelope cloudflareEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(&envelope); decodeErr != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("cloudflare API response is invalid: %w", decodeErr)
	}
	if !envelope.Success || len(envelope.Errors) != 0 || len(envelope.Result) == 0 {
		return fmt.Errorf("cloudflare API reported failure")
	}
	if output != nil {
		if err := json.Unmarshal(envelope.Result, output); err != nil {
			return fmt.Errorf("cloudflare API result is invalid: %w", err)
		}
	}
	return nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
