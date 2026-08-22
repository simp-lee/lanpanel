//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
)

func RunFixtureRole(args []string) error {
	if len(args) != 0 || os.Getenv("LANPANEL_HTTP_SOCKET") != "/proc/self/fd/3" || os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_FDNAMES") != "lanpanel-http" {
		return fmt.Errorf("qualification fixture requires one managed socket-activation endpoint")
	}
	file := os.NewFile(3, "qualification-http")
	if file == nil {
		return fmt.Errorf("qualification fixture listener is unavailable")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/echo", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(writer).Encode(struct {
			Host            string `json:"host"`
			Authorization   string `json:"authorization"`
			Forwarded       string `json:"forwarded"`
			XForwardedFor   string `json:"x_forwarded_for"`
			XForwardedHost  string `json:"x_forwarded_host"`
			XForwardedProto string `json:"x_forwarded_proto"`
			XRealIP         string `json:"x_real_ip"`
			CFConnectingIP  string `json:"cf_connecting_ip"`
			TrueClientIP    string `json:"true_client_ip"`
		}{request.Host, request.Header.Get("Authorization"), request.Header.Get("Forwarded"), request.Header.Get("X-Forwarded-For"), request.Header.Get("X-Forwarded-Host"), request.Header.Get("X-Forwarded-Proto"), request.Header.Get("X-Real-IP"), request.Header.Get("CF-Connecting-IP"), request.Header.Get("True-Client-IP")})
	})
	mux.HandleFunc("/ws", func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
		if err != nil {
			return
		}
		defer func() { _ = connection.Close(websocket.StatusNormalClosure, "complete") }()
		ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
		defer cancel()
		kind, message, err := connection.Read(ctx)
		if err == nil && len(message) <= 4096 && !strings.ContainsRune(string(message), '\x00') {
			_ = connection.Write(ctx, kind, message)
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	err = server.Serve(listener)
	if err == http.ErrServerClosed || err == io.EOF {
		return nil
	}
	return err
}
