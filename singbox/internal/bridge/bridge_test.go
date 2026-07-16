package bridge

import (
	"context"
	"errors"
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
