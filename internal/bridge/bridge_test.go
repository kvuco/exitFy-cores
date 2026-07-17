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
	escaped := SafeError(`{"password":"prefix\\\"still-secret suffix"}`)
	if strings.Contains(escaped, "still-secret") || strings.Contains(escaped, "suffix") {
		t.Fatalf("escaped JSON credential survived sanitization: %s", escaped)
	}
	plain := SafeError(`username="private user" password:'private password' id=private-id`)
	if strings.Contains(plain, "private user") || strings.Contains(plain, "private password") ||
		strings.Contains(plain, "private-id") {
		t.Fatalf("plain credential survived sanitization: %s", plain)
	}
}

func TestSafeErrorRedactsMultiwordAndNonStringJSONValues(t *testing.T) {
	plain := SafeError("Authorization=Bearer first second third, battery staple")
	for _, forbidden := range []string{
		"Bearer", "first", "second", "third", "battery", "staple",
	} {
		if strings.Contains(plain, forbidden) {
			t.Fatalf("unquoted credential tail survived sanitization: %q", plain)
		}
	}
	semicolon := SafeError("Authorization=Bearer abc;def")
	if strings.Contains(semicolon, "abc") || strings.Contains(semicolon, "def") {
		t.Fatalf("semicolon credential tail survived sanitization: %q", semicolon)
	}
	brackets := SafeError("password=correct horse]battery}staple")
	for _, forbidden := range []string{"correct", "horse", "battery", "staple"} {
		if strings.Contains(brackets, forbidden) {
			t.Fatalf("bracket credential tail survived sanitization: %q", brackets)
		}
	}
	safeTail := SafeError("password=secret words, status=retryable")
	if strings.Contains(safeTail, "secret") || strings.Contains(safeTail, "status=retryable") {
		t.Fatalf("ambiguous credential tail was not redacted fail-closed: %q", safeTail)
	}
	unknownTail := SafeError("password=secret words, message=battery staple")
	if strings.Contains(unknownTail, "secret") || strings.Contains(unknownTail, "battery") {
		t.Fatalf("unproven diagnostic tail escaped fail-closed redaction: %q", unknownTail)
	}
	newlineContinuation := SafeError("Authorization=Bearer abc\ncontinued-secret")
	if strings.Contains(newlineContinuation, "abc") ||
		strings.Contains(newlineContinuation, "continued-secret") {
		t.Fatalf("newline credential continuation survived sanitization: %q",
			newlineContinuation)
	}
	newlineSafeTail := SafeError("password=secret\nstatus=retryable")
	if strings.Contains(newlineSafeTail, "secret") ||
		strings.Contains(newlineSafeTail, "status=retryable") {
		t.Fatalf("ambiguous newline credential tail was not redacted: %q", newlineSafeTail)
	}
	malformedJSONContinuation := SafeError(
		"{\"authorization\":Bearer abc\ncontinued-secret}")
	if strings.Contains(malformedJSONContinuation, "abc") ||
		strings.Contains(malformedJSONContinuation, "continued-secret") {
		t.Fatalf("malformed JSON credential continuation survived sanitization: %q",
			malformedJSONContinuation)
	}
	malformedJSONSafeTail := SafeError(
		"{\"password\":secret\n\"status\":\"retryable\"}")
	if strings.Contains(malformedJSONSafeTail, "secret") ||
		strings.Contains(malformedJSONSafeTail, `"status":"retryable"`) {
		t.Fatalf("malformed JSON credential tail was not redacted fail-closed: %q",
			malformedJSONSafeTail)
	}

	jsonValue := SafeError(`{"token":123456789,"hwid":false,"password":null,` +
		`"authorization":["Bearer",{"secret":"nested-value"}],"ok":true}`)
	for _, forbidden := range []string{
		"123456789", "false", "null", "Bearer", "nested-value",
	} {
		if strings.Contains(jsonValue, forbidden) {
			t.Fatalf("non-string JSON credential survived sanitization: %q", jsonValue)
		}
	}
	if !strings.Contains(jsonValue, `"ok":true`) {
		t.Fatalf("redaction consumed an unrelated JSON field: %q", jsonValue)
	}
	for _, malformed := range []string{
		`{"token":123] trailing-primitive-secret, "ok":true}`,
		`{"token":"hidden" trailing-string-secret, "ok":true}`,
		`{"token":{"nested":"hidden"} trailing-object-secret, "ok":true}`,
		`{"token":["hidden"]] trailing-array-secret, "ok":true}`,
	} {
		clean := SafeError(malformed)
		if strings.Contains(clean, "trailing-") || strings.Contains(clean, "hidden") {
			t.Fatalf("malformed JSON credential tail survived sanitization: %q", clean)
		}
	}
}

func TestSafeErrorDecodesEscapedKeysAndCoversCoreCredentials(t *testing.T) {
	value := SafeError(`{"to\u006ben":"token-secret","AUTH_\u0053TR":"auth-secret",` +
		`"pass":"inbound-secret","obfs":"obfs-secret","encryption":"enc-secret",` +
		`"private_\u006bey":"private-secret","pre_shared_key":"psk-secret",` +
		`"path":"/credential-path","headers":{"Cookie":"cookie-secret"},"ok":true}`)
	for _, forbidden := range []string{
		"token-secret", "auth-secret", "inbound-secret", "obfs-secret", "enc-secret",
		"private-secret", "psk-secret", "credential-path", "cookie-secret",
	} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("escaped/aliased credential survived sanitization: %q", value)
		}
	}
	if !strings.Contains(value, `"ok":true`) {
		t.Fatalf("sanitization consumed unrelated JSON: %q", value)
	}
	plain := SafeError(`password="quoted-secret" trailing-secret`)
	if strings.Contains(plain, "quoted-secret") || strings.Contains(plain, "trailing-secret") {
		t.Fatalf("quoted plain credential tail survived sanitization: %q", plain)
	}
	malformedQuotedKey := SafeError(`{'password':'single-quoted-secret', 'ok':true}`)
	if strings.Contains(malformedQuotedKey, "single-quoted-secret") ||
		strings.Contains(malformedQuotedKey, `'ok':true`) {
		t.Fatalf("single-quoted malformed credential survived: %q", malformedQuotedKey)
	}
}

func TestSafeErrorCapsRawInputBeforeRedaction(t *testing.T) {
	boundary := strings.Repeat("a", maxSanitizeInputBytes-1) + "🚀tail"
	prefix := boundedSanitizeInput(boundary)
	if len(prefix) != maxSanitizeInputBytes-1 {
		t.Fatalf("UTF-8 prefix was cut at an unsafe boundary: %d", len(prefix))
	}
	hugeJSON := `{"auth_str":"` + strings.Repeat("never-log-", maxSanitizeInputBytes) + `"}`
	cleanJSON := SafeError(hugeJSON)
	if strings.Contains(cleanJSON, "never-log") {
		t.Fatalf("huge truncated JSON credential survived: %q", cleanJSON)
	}
	hugeURI := `vless://user:` + strings.Repeat("uri-secret", maxSanitizeInputBytes) +
		`@example.test:443`
	cleanURI := SafeError(hugeURI)
	if strings.Contains(cleanURI, "uri-secret") || strings.Contains(cleanURI, "example.test") {
		t.Fatalf("huge URI credential survived: %q", cleanURI)
	}
	for _, clean := range []string{cleanJSON, cleanURI} {
		if len([]rune(clean)) > maxErrorRunes || len([]byte(clean)) > maxErrorBytes {
			t.Fatalf("bounded sanitizer exceeded output cap: %d/%d",
				len([]rune(clean)), len([]byte(clean)))
		}
	}
}

func TestFailedStartResponseRequiresSerializedStopBeforeRetry(t *testing.T) {
	lifecycle.Lock()
	lifecycle.running = false
	lifecycle.stopRequired = false
	lifecycle.Unlock()
	originalInvoke := invokeLibXray
	defer func() {
		invokeLibXray = originalInvoke
		lifecycle.Lock()
		lifecycle.running = false
		lifecycle.stopRequired = false
		lifecycle.Unlock()
	}()

	stopCalls := 0
	invokeLibXray = func(request string) string {
		var envelope struct {
			APIVersion int    `json:"apiVersion"`
			Method     string `json:"method"`
		}
		if err := json.Unmarshal([]byte(request), &envelope); err != nil {
			t.Fatalf("invalid invoke envelope: %v", err)
		}
		if envelope.APIVersion != 1 {
			t.Fatalf("unexpected libXray API version: %d", envelope.APIVersion)
		}
		if strings.Contains(request, `"method":"stopXray"`) {
			stopCalls++
			return `{"success":true,"error":""}`
		}
		return `{"success":false,"error":"uncertain start"}`
	}
	if err := Start(`{"log":{"loglevel":"none"}}`); err == nil {
		t.Fatal("failed libXray response was accepted")
	}
	if err := Start(`{"log":{"loglevel":"none"}}`); err == nil {
		t.Fatal("retry was accepted before serialized stop")
	}
	if err := Stop(); err != nil {
		t.Fatalf("cleanup stop: %v", err)
	}
	if stopCalls != 1 {
		t.Fatalf("expected one stopXray cleanup, got %d", stopCalls)
	}
}

func TestStopErrorIsReturnedAndRetryable(t *testing.T) {
	lifecycle.Lock()
	lifecycle.running = false
	lifecycle.stopRequired = false
	lifecycle.Unlock()
	originalInvoke := invokeLibXray
	defer func() {
		invokeLibXray = originalInvoke
		lifecycle.Lock()
		lifecycle.running = false
		lifecycle.stopRequired = false
		lifecycle.Unlock()
	}()

	stopCalls := 0
	invokeLibXray = func(request string) string {
		if strings.Contains(request, `"method":"stopXray"`) {
			stopCalls++
			if stopCalls == 1 {
				return `{"success":false,"error":"stop failed"}`
			}
		}
		return `{"success":true,"error":""}`
	}
	if err := Start(`{"log":{"loglevel":"none"}}`); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := Stop(); err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("Stop error was lost: %v", err)
	}
	if err := Start(`{"log":{"loglevel":"none"}}`); err == nil {
		t.Fatal("start was accepted before successful Stop retry")
	}
	if err := Stop(); err != nil {
		t.Fatalf("Stop retry: %v", err)
	}
}

func TestStartPanicIsContainedSanitizedAndRequiresStop(t *testing.T) {
	lifecycle.Lock()
	lifecycle.running = false
	lifecycle.stopRequired = false
	lifecycle.Unlock()
	originalInvoke := invokeLibXray
	defer func() {
		invokeLibXray = originalInvoke
		lifecycle.Lock()
		lifecycle.running = false
		lifecycle.stopRequired = false
		lifecycle.Unlock()
	}()

	invokeLibXray = func(request string) string {
		if strings.Contains(request, `"method":"stopXray"`) {
			return `{"success":true,"error":""}`
		}
		panic(`vless://secret@example.test:443`)
	}
	err := Start(`{"log":{"loglevel":"none"}}`)
	if err == nil || !strings.Contains(err.Error(), "start panic") {
		t.Fatalf("start panic escaped or was lost: %v", err)
	}
	if strings.Contains(err.Error(), "secret@example") {
		t.Fatalf("panic credential survived sanitization: %v", err)
	}
	if err := Start(`{"log":{"loglevel":"none"}}`); err == nil {
		t.Fatal("start retry was accepted before StopCore")
	}
	if err := Stop(); err != nil {
		t.Fatalf("cleanup after panic: %v", err)
	}
}

func TestStopPanicIsContainedAndRetryable(t *testing.T) {
	lifecycle.Lock()
	lifecycle.running = false
	lifecycle.stopRequired = false
	lifecycle.Unlock()
	originalInvoke := invokeLibXray
	defer func() {
		invokeLibXray = originalInvoke
		lifecycle.Lock()
		lifecycle.running = false
		lifecycle.stopRequired = false
		lifecycle.Unlock()
	}()

	stopCalls := 0
	invokeLibXray = func(request string) string {
		if strings.Contains(request, `"method":"stopXray"`) {
			stopCalls++
			if stopCalls == 1 {
				panic("stop panic")
			}
		}
		return `{"success":true,"error":""}`
	}
	if err := Start(`{"log":{"loglevel":"none"}}`); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := Stop(); err == nil || !strings.Contains(err.Error(), "stop panic") {
		t.Fatalf("stop panic escaped or was lost: %v", err)
	}
	if err := Stop(); err != nil {
		t.Fatalf("stop retry: %v", err)
	}
	if stopCalls != 2 {
		t.Fatalf("expected two serialized stop attempts, got %d", stopCalls)
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
