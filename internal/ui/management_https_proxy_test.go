package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementHTTPSProxyUsesExternalOriginAndSecureSessionCookie(t *testing.T) {
	server := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "https://management.example.test/login", strings.NewReader("token=admin"))
	request.Host = "management.example.test"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Origin", "https://management.example.test")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	writer := httptest.NewRecorder()
	server.ServeHTTP(writer, request)
	if writer.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", writer.Code, writer.Body.String())
	}
	cookies := writer.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure {
		t.Fatalf("expected one Secure session cookie, got %#v", cookies)
	}
}
