package bridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

const validConfig = `{
  "log":{"level":"panic"},
  "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":0}],
  "outbounds":[{"type":"direct","tag":"proxy"}],
  "route":{"final":"proxy"}
}`

type fakeCore struct {
	start func() error
	close func() error
}

func (f *fakeCore) Start() error {
	if f.start != nil {
		return f.start()
	}
	return nil
}

func (f *fakeCore) Close() error {
	if f.close != nil {
		return f.close()
	}
	return nil
}

func withFactory(t *testing.T, factory coreFactory) {
	t.Helper()
	_ = Stop()
	original := newCore
	newCore = factory
	t.Cleanup(func() {
		_ = Stop()
		newCore = original
	})
}

func TestRejectsMalformedAndOversizedConfiguration(t *testing.T) {
	withFactory(t, func(context.Context, option.Options) (core, error) {
		return &fakeCore{}, nil
	})
	if err := Start(`{"inbounds":`); err == nil {
		t.Fatal("malformed configuration was accepted")
	}
	if err := Start(strings.Repeat("x", MaxConfigBytes+1)); err == nil {
		t.Fatal("oversized configuration was accepted")
	}
}

func TestLifecycleIsIdempotentAndRejectsDoubleStart(t *testing.T) {
	starts := 0
	stops := 0
	withFactory(t, func(context.Context, option.Options) (core, error) {
		return &fakeCore{
			start: func() error { starts++; return nil },
			close: func() error { stops++; return nil },
		}, nil
	})
	if err := Start(validConfig); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := Start(validConfig); err == nil {
		t.Fatal("double start was accepted")
	}
	if err := Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := Stop(); err != nil {
		t.Fatalf("repeated stop: %v", err)
	}
	if starts != 1 || stops != 1 {
		t.Fatalf("unexpected lifecycle calls: starts=%d stops=%d", starts, stops)
	}
}

func TestFailedStartCleansUpAndAllowsRetry(t *testing.T) {
	attempt := 0
	closed := 0
	withFactory(t, func(context.Context, option.Options) (core, error) {
		attempt++
		current := attempt
		return &fakeCore{
			start: func() error {
				if current == 1 {
					return errors.New("expected failure")
				}
				return nil
			},
			close: func() error { closed++; return nil },
		}, nil
	})
	if err := Start(validConfig); err == nil {
		t.Fatal("failed start was accepted")
	}
	if IsRunning() {
		t.Fatal("failed start left core running")
	}
	if err := Start(validConfig); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := Stop(); err != nil {
		t.Fatalf("stop retry: %v", err)
	}
	if closed != 2 {
		t.Fatalf("expected both candidates to close, got %d", closed)
	}
}

func TestFactoryErrorClosesNonNilCandidateAndAllowsRetry(t *testing.T) {
	attempts := 0
	closed := 0
	withFactory(t, func(context.Context, option.Options) (core, error) {
		attempts++
		candidate := &fakeCore{close: func() error { closed++; return nil }}
		if attempts == 1 {
			return candidate, errors.New("partial factory failure")
		}
		return candidate, nil
	})
	if err := Start(validConfig); err == nil {
		t.Fatal("partial factory failure was accepted")
	}
	if closed != 1 {
		t.Fatalf("partial candidate was not closed exactly once: %d", closed)
	}
	if err := Start(validConfig); err != nil {
		t.Fatalf("retry after successful partial cleanup: %v", err)
	}
	if err := Stop(); err != nil {
		t.Fatalf("stop retry: %v", err)
	}
	if closed != 2 {
		t.Fatalf("successful retry candidate was not closed: %d", closed)
	}
}

func TestFactoryErrorWithFailedCleanupRequiresStop(t *testing.T) {
	closeAttempts := 0
	withFactory(t, func(context.Context, option.Options) (core, error) {
		return &fakeCore{close: func() error {
			closeAttempts++
			if closeAttempts == 1 {
				return errors.New("partial cleanup failed")
			}
			return nil
		}}, errors.New("partial factory failure")
	})
	err := Start(validConfig)
	if err == nil || !strings.Contains(err.Error(), "partial cleanup failed") {
		t.Fatalf("partial cleanup error was lost: %v", err)
	}
	if err := Start(validConfig); err == nil {
		t.Fatal("retry was accepted before StopCore cleaned partial candidate")
	}
	if err := Stop(); err != nil {
		t.Fatalf("serialized partial cleanup stop: %v", err)
	}
	if closeAttempts != 2 {
		t.Fatalf("partial cleanup was not retried exactly once: %d", closeAttempts)
	}
}

func TestFailedStartWithFailedCleanupRequiresStop(t *testing.T) {
	closeAttempts := 0
	withFactory(t, func(context.Context, option.Options) (core, error) {
		return &fakeCore{
			start: func() error { return errors.New("uncertain start") },
			close: func() error {
				closeAttempts++
				if closeAttempts == 1 {
					return errors.New("cleanup failed")
				}
				return nil
			},
		}, nil
	})
	if err := Start(validConfig); err == nil {
		t.Fatal("failed start was accepted")
	}
	if err := Start(validConfig); err == nil {
		t.Fatal("retry was accepted before StopCore")
	}
	if err := Stop(); err != nil {
		t.Fatalf("serialized cleanup stop: %v", err)
	}
}

func TestFailedStartWithPanickingCleanupRequiresStop(t *testing.T) {
	closeAttempts := 0
	withFactory(t, func(context.Context, option.Options) (core, error) {
		return &fakeCore{
			start: func() error { return errors.New("uncertain start") },
			close: func() error {
				closeAttempts++
				if closeAttempts == 1 {
					panic("cleanup panic")
				}
				return nil
			},
		}, nil
	})
	if err := Start(validConfig); err == nil || !strings.Contains(err.Error(), "cleanup panic") {
		t.Fatalf("cleanup panic was not contained: %v", err)
	}
	if err := Start(validConfig); err == nil {
		t.Fatal("retry was accepted before StopCore")
	}
	if err := Stop(); err != nil {
		t.Fatalf("serialized cleanup stop: %v", err)
	}
}

func TestStopWaitsForSerializedStart(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	withFactory(t, func(context.Context, option.Options) (core, error) {
		return &fakeCore{start: func() error {
			close(entered)
			<-release
			return nil
		}}, nil
	})
	startDone := make(chan error, 1)
	go func() { startDone <- Start(validConfig) }()
	<-entered
	stopDone := make(chan error, 1)
	go func() { stopDone <- Stop() }()
	select {
	case <-stopDone:
		t.Fatal("Stop raced a running Start")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-startDone; err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := <-stopDone; err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestStopErrorIsReturnedAndRetryable(t *testing.T) {
	closeAttempts := 0
	withFactory(t, func(context.Context, option.Options) (core, error) {
		return &fakeCore{close: func() error {
			closeAttempts++
			if closeAttempts == 1 {
				return errors.New("stop failed")
			}
			return nil
		}}, nil
	})
	if err := Start(validConfig); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := Stop(); err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("Stop error was lost: %v", err)
	}
	if err := Start(validConfig); err == nil {
		t.Fatal("start was accepted before successful Stop retry")
	}
	if err := Stop(); err != nil {
		t.Fatalf("Stop retry: %v", err)
	}
}

func TestJoinedClosedAndRealCleanupErrorRemainsRetryable(t *testing.T) {
	closeAttempts := 0
	withFactory(t, func(context.Context, option.Options) (core, error) {
		return &fakeCore{close: func() error {
			closeAttempts++
			if closeAttempts == 1 {
				return errors.Join(os.ErrClosed, errors.New("listener cleanup failed"))
			}
			return nil
		}}, nil
	})
	if err := Start(validConfig); err != nil {
		t.Fatalf("start: %v", err)
	}
	err := Stop()
	if err == nil || !strings.Contains(err.Error(), "listener cleanup failed") {
		t.Fatalf("joined real cleanup failure was discarded: %v", err)
	}
	if err := Start(validConfig); err == nil {
		t.Fatal("start was accepted while joined cleanup failure remained")
	}
	if err := Stop(); err != nil {
		t.Fatalf("serialized cleanup retry: %v", err)
	}
	if closeAttempts != 2 {
		t.Fatalf("unexpected cleanup attempts: %d", closeAttempts)
	}

	if !isOnlyClosed(fmt.Errorf("already closed: %w", os.ErrClosed)) {
		t.Fatal("a single wrapped os.ErrClosed was not treated as complete")
	}
	if !isOnlyClosed(errors.Join(os.ErrClosed, fmt.Errorf("nested: %w", os.ErrClosed))) {
		t.Fatal("an all-closed error tree was not treated as complete")
	}
}

func TestFactoryPanicIsContainedAndSanitized(t *testing.T) {
	withFactory(t, func(context.Context, option.Options) (core, error) {
		panic(`vless://secret@example.test:443`)
	})
	err := Start(validConfig)
	if err == nil || !strings.Contains(err.Error(), "start panic") {
		t.Fatalf("factory panic escaped or was lost: %v", err)
	}
	if strings.Contains(err.Error(), "secret@example") {
		t.Fatalf("panic credential survived sanitization: %v", err)
	}
	newCore = func(context.Context, option.Options) (core, error) {
		return &fakeCore{}, nil
	}
	if err := Start(validConfig); err != nil {
		t.Fatalf("clean retry after pre-instance panic: %v", err)
	}
}

func TestStopCancelPanicIsContainedAndStateIsRetryable(t *testing.T) {
	withFactory(t, func(context.Context, option.Options) (core, error) {
		return &fakeCore{}, nil
	})
	if err := Start(validConfig); err != nil {
		t.Fatalf("start: %v", err)
	}
	lifecycle.Lock()
	lifecycle.cancel = func() { panic(`https://example.test/private`) }
	lifecycle.Unlock()
	err := Stop()
	if err == nil || !strings.Contains(err.Error(), "stop panic") {
		t.Fatalf("cancel panic escaped or was lost: %v", err)
	}
	if strings.Contains(err.Error(), "example.test/private") {
		t.Fatalf("panic URL survived sanitization: %v", err)
	}
	lifecycle.Lock()
	if lifecycle.instance == nil || !lifecycle.stopRequired {
		lifecycle.Unlock()
		t.Fatal("uncertain stop did not retain retryable state")
	}
	lifecycle.cancel = nil
	lifecycle.Unlock()
	if err := Stop(); err != nil {
		t.Fatalf("stop retry: %v", err)
	}
}

func TestConcurrentStartsCreateOneInstance(t *testing.T) {
	var access sync.Mutex
	created := 0
	withFactory(t, func(context.Context, option.Options) (core, error) {
		access.Lock()
		created++
		access.Unlock()
		return &fakeCore{}, nil
	})
	results := make(chan error, 2)
	go func() { results <- Start(validConfig) }()
	go func() { results <- Start(validConfig) }()
	first := <-results
	second := <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("expected one success and one rejection: %v / %v", first, second)
	}
	if created != 1 {
		t.Fatalf("created %d instances", created)
	}
}

func TestSafeErrorRedactsAndBoundsUnicode(t *testing.T) {
	value := `https://example.com/private vless://uuid@example.com:443 ` +
		`{"password":"do-not-log\\\"still-secret"}` + strings.Repeat("🙂", 2000)
	clean := SafeError(value)
	for _, forbidden := range []string{"example.com/private", "uuid@example", "do-not-log", "still-secret"} {
		if strings.Contains(clean, forbidden) {
			t.Fatalf("secret survived sanitization: %q", clean)
		}
	}
	if len([]rune(clean)) > maxErrorRunes || len([]byte(clean)) > maxErrorBytes {
		t.Fatalf("error exceeds bounds: runes=%d bytes=%d", len([]rune(clean)), len([]byte(clean)))
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

func TestSupportedFixtureMatrixStarts(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	directory := filepath.Join(filepath.Dir(source), "..", "..", "testdata")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" ||
			strings.HasPrefix(entry.Name(), "unsupported-") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			value, readError := os.ReadFile(filepath.Join(directory, entry.Name()))
			if readError != nil {
				t.Fatal(readError)
			}
			if startError := Start(string(value)); startError != nil {
				t.Fatalf("start fixture: %v", startError)
			}
			if stopError := Stop(); stopError != nil {
				t.Fatalf("stop fixture: %v", stopError)
			}
		})
	}
}

func TestUnsupportedBuildFeatureIsRejected(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(source), "..", "..", "testdata",
		"unsupported-wireguard.json")
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = Start(string(value)); err == nil {
		_ = Stop()
		t.Fatal("unsupported WireGuard endpoint was accepted")
	}
}
