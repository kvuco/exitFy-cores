package bridge

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
)

func TestStartRejectsInvalidConfiguration(t *testing.T) {
	if err := Start(""); err == nil {
		t.Fatal("empty configuration was accepted")
	}
	if err := Start("{"); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
	if err := Start("[]"); err == nil {
		t.Fatal("non-object configuration was accepted")
	}
	fixture, err := os.ReadFile("../../testdata/xray-corrupt.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := Start(string(fixture)); err == nil {
		t.Fatal("corrupted fixture was accepted")
	}
}

func TestLifecycle(t *testing.T) {
	_ = Stop()
	port := freePort(t)
	config, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "blackhole",
			"tag":      "smoke",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Start(string(config)); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !IsRunning() {
		t.Fatal("running state was not recorded")
	}
	if err := Start(string(config)); err == nil {
		t.Fatal("double start was accepted")
	}
	if err := Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if IsRunning() {
		t.Fatal("running state survived stop")
	}
	if err := Stop(); err != nil {
		t.Fatalf("idempotent stop: %v", err)
	}
}

func TestSafeErrorBoundsAndStripsControls(t *testing.T) {
	value := SafeError("\x00" + strings.Repeat("🚀", 2048))
	if strings.ContainsRune(value, '\x00') {
		t.Fatal("control character survived")
	}
	if len([]rune(value)) > maxErrorRunes || len([]byte(value)) > maxErrorBytes {
		t.Fatalf("unbounded error: %d runes/%d bytes", len([]rune(value)), len(value))
	}
	secret := SafeError(`vless://uuid@example.test:443 "password":"do-not-log"`)
	if strings.Contains(secret, "uuid@example") || strings.Contains(secret, "do-not-log") {
		t.Fatalf("credential survived sanitization: %s", secret)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
