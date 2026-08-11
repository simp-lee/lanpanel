package edgeone

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	Service = "teo"
	Host    = "teo.tencentcloudapi.com"
	// Endpoint is the Tencent Cloud China EdgeOne API endpoint for DescribeOriginACL.
	Endpoint                  = "https://teo.tencentcloudapi.com"
	Version                   = "2022-09-01"
	ActionDescribeOriginACL   = "DescribeOriginACL"
	AlgorithmTC3HMACSHA256    = "TC3-HMAC-SHA256"
	OriginACLStatusOnline     = "online"
	OriginACLStatusUpdating   = "updating"
	signedHeaders             = "content-type;host"
	canonicalContentTypeValue = "application/json; charset=utf-8"
	DescribeOriginACLTimeout  = 30 * time.Second
)

var defaultHTTPClient HTTPDoer = &http.Client{Timeout: DescribeOriginACLTimeout}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	HTTPClient HTTPDoer
	Endpoint   string
	Now        func() time.Time
}

type OriginACLInfo struct {
	Status           string     `json:"Status"`
	L7Hosts          []string   `json:"L7Hosts"`
	OriginACLFamily  string     `json:"OriginACLFamily"`
	CurrentOriginACL *OriginACL `json:"CurrentOriginACL"`
	NextOriginACL    *OriginACL `json:"NextOriginACL"`
}

type OriginACL struct {
	Version           string    `json:"Version"`
	ActiveTime        string    `json:"ActiveTime"`
	PlannedActiveTime string    `json:"PlannedActiveTime"`
	EntireAddresses   Addresses `json:"EntireAddresses"`
}

type Addresses struct {
	IPv4 []string `json:"IPv4"`
	IPv6 []string `json:"IPv6"`
}

type describeOriginACLResponse struct {
	Response struct {
		OriginACLInfo *OriginACLInfo `json:"OriginACLInfo"`
		RequestID     string         `json:"RequestId"`
		Error         *apiError      `json:"Error"`
	} `json:"Response"`
}

type apiError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

func (client Client) DescribeOriginACL(ctx context.Context, credentials Credentials, zoneID string) (*OriginACLInfo, error) {
	zoneID = strings.TrimSpace(zoneID)
	if zoneID == "" {
		return nil, fmt.Errorf("edgeone zone_id is required")
	}
	payload, err := json.Marshal(map[string]string{"ZoneId": zoneID})
	if err != nil {
		return nil, fmt.Errorf("marshal DescribeOriginACL request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint(), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build DescribeOriginACL request: %w", err)
	}
	now := time.Now().UTC()
	if client.Now != nil {
		now = client.Now().UTC()
	}
	if err := SignRequest(request, credentials, now, payload); err != nil {
		return nil, err
	}

	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = defaultHTTPClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call EdgeOne DescribeOriginACL: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read EdgeOne DescribeOriginACL response: %w", err)
	}
	var parsed describeOriginACLResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("decode EdgeOne DescribeOriginACL response status %d: %w", response.StatusCode, err)
	}
	if parsed.Response.Error != nil {
		return nil, fmt.Errorf("EdgeOne DescribeOriginACL failed: %s: %s", parsed.Response.Error.Code, parsed.Response.Error.Message)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("EdgeOne DescribeOriginACL returned HTTP status %d", response.StatusCode)
	}
	if parsed.Response.OriginACLInfo == nil {
		return nil, fmt.Errorf("EdgeOne DescribeOriginACL response missing OriginACLInfo")
	}
	return parsed.Response.OriginACLInfo, nil
}

func (client Client) endpoint() string {
	if strings.TrimSpace(client.Endpoint) != "" {
		return strings.TrimSpace(client.Endpoint)
	}
	return Endpoint
}

func SignRequest(request *http.Request, credentials Credentials, now time.Time, payload []byte) error {
	if request == nil || request.URL == nil || strings.TrimSpace(request.URL.Host) == "" {
		return fmt.Errorf("EdgeOne request URL host is required for signing")
	}
	host := strings.TrimSpace(request.URL.Host)
	authorization, err := Authorization(credentials.SecretID, credentials.SecretKey, now, payload, host)
	if err != nil {
		return err
	}
	timestamp := now.Unix()
	request.Header.Set("Content-Type", canonicalContentTypeValue)
	request.Host = host
	request.Header.Set("Host", host)
	request.Header.Set("X-TC-Action", ActionDescribeOriginACL)
	request.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", timestamp))
	request.Header.Set("X-TC-Version", Version)
	if credentials.SessionToken != "" {
		request.Header.Set("X-TC-Token", credentials.SessionToken)
	}
	request.Header.Set("Authorization", authorization)
	return nil
}

func Authorization(secretID string, secretKey string, now time.Time, payload []byte, host string) (string, error) {
	secretID = strings.TrimSpace(secretID)
	secretKey = strings.TrimSpace(secretKey)
	host = strings.TrimSpace(host)
	if secretID == "" {
		return "", fmt.Errorf("EdgeOne secret id is required for signing")
	}
	if secretKey == "" {
		return "", fmt.Errorf("EdgeOne secret key is required for signing")
	}
	if host == "" {
		return "", fmt.Errorf("EdgeOne host is required for signing")
	}
	date := now.UTC().Format("2006-01-02")
	credentialScope := date + "/" + Service + "/tc3_request"
	hashedPayload := sha256Hex(payload)
	canonicalHeaders := "content-type:" + canonicalContentTypeValue + "\n" + "host:" + host + "\n"
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"",
		canonicalHeaders,
		signedHeaders,
		hashedPayload,
	}, "\n")
	hashedCanonicalRequest := sha256Hex([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		AlgorithmTC3HMACSHA256,
		fmt.Sprintf("%d", now.UTC().Unix()),
		credentialScope,
		hashedCanonicalRequest,
	}, "\n")
	secretDate := hmacSHA256([]byte("TC3"+secretKey), []byte(date))
	secretService := hmacSHA256(secretDate, []byte(Service))
	secretSigning := hmacSHA256(secretService, []byte("tc3_request"))
	signature := hex.EncodeToString(hmacSHA256(secretSigning, []byte(stringToSign)))
	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", AlgorithmTC3HMACSHA256, secretID, credentialScope, signedHeaders, signature), nil
}

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func hmacSHA256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}
