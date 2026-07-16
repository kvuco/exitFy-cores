package bridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	SJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

const (
	MaxConfigBytes = 16 << 20
	maxErrorRunes  = 1024
	maxErrorBytes  = 4096
)

var (
	proxyURI = regexp.MustCompile(
		`(?i)\b(?:vless|vmess|trojan|ss|hy2|hysteria2?|tuic)://\S+`,
	)
	httpURL    = regexp.MustCompile(`(?i)https?://\S+`)
	jsonSecret = regexp.MustCompile(
		`(?i)"(?:password|passwd|token|secret|uuid|authorization|hwid|username|user|id)"\s*:\s*"(?:\\.|[^"\\])*"`,
	)
	newCore = createCore
)

type core interface {
	Start() error
	Close() error
}

type coreFactory func(context.Context, option.Options) (core, error)

var lifecycle struct {
	sync.Mutex
	instance     core
	cancel       context.CancelFunc
	stopRequired bool
}

// Start validates untrusted JSON and starts exactly one process-global core.
// Holding the lifecycle lock through Start deliberately serializes StopCore
// behind a slow or hung native start, matching exitFy's JNI contract.
func Start(configJSON string) (err error) {
	lifecycle.Lock()
	defer lifecycle.Unlock()

	configJSON = strings.TrimSpace(configJSON)
	if configJSON == "" {
		return errors.New("empty SB core configuration")
	}
	if len(configJSON) > MaxConfigBytes {
		return fmt.Errorf("SB core configuration exceeds %d bytes", MaxConfigBytes)
	}
	if lifecycle.instance != nil || lifecycle.stopRequired {
		return errors.New("SB core is already running or requires StopCore")
	}

	baseCtx := context.Background()
	baseCtx = service.ContextWith(baseCtx, deprecated.NewStderrManager(log.StdLogger()))
	baseCtx = include.Context(baseCtx)
	options, err := SJSON.UnmarshalExtendedContext[option.Options](
		baseCtx, []byte(configJSON),
	)
	if err != nil {
		return fmt.Errorf("invalid SB core configuration: %w", err)
	}

	runCtx, cancel := context.WithCancel(baseCtx)
	var candidate core
	defer func() {
		if recovered := recover(); recovered != nil {
			cancel()
			if candidate != nil {
				if closeError := closeCore(candidate); !closedOrNil(closeError) {
					lifecycle.instance = candidate
					lifecycle.cancel = cancel
					lifecycle.stopRequired = true
				}
			}
			err = fmt.Errorf("SB core start panic: %v", recovered)
		}
	}()

	candidate, err = newCore(runCtx, options)
	if err != nil {
		cancel()
		return fmt.Errorf("create SB core: %w", err)
	}
	if err = candidate.Start(); err != nil {
		cancel()
		if closeError := closeCore(candidate); !closedOrNil(closeError) {
			lifecycle.instance = candidate
			lifecycle.cancel = cancel
			lifecycle.stopRequired = true
			return fmt.Errorf("start SB core: %w; cleanup: %v", err, closeError)
		}
		return fmt.Errorf("start SB core: %w", err)
	}
	lifecycle.instance = candidate
	lifecycle.cancel = cancel
	lifecycle.stopRequired = false
	return nil
}

// Stop is synchronized and idempotent. ABI 2 returns a sanitized Close error
// to the Java/JNI caller instead of silently losing it.
func Stop() (err error) {
	lifecycle.Lock()
	defer lifecycle.Unlock()

	if lifecycle.instance == nil {
		lifecycle.stopRequired = false
		return nil
	}
	instance := lifecycle.instance
	cancel := lifecycle.cancel
	lifecycle.stopRequired = true
	if cancel != nil {
		cancel()
	}
	if closeError := closeCore(instance); closeError != nil {
		if !errors.Is(closeError, os.ErrClosed) {
			return fmt.Errorf("stop SB core: %w", closeError)
		}
	}
	lifecycle.instance = nil
	lifecycle.cancel = nil
	lifecycle.stopRequired = false
	return nil
}

func IsRunning() bool {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	return lifecycle.instance != nil && !lifecycle.stopRequired
}

func closedOrNil(err error) bool {
	return err == nil || errors.Is(err, os.ErrClosed)
}

func closeCore(instance core) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("core close panic: %v", recovered)
		}
	}()
	return instance.Close()
}

func createCore(ctx context.Context, options option.Options) (core, error) {
	return box.New(box.Options{Context: ctx, Options: options})
}

// SafeError bounds errors crossing the native boundary and removes values
// which may contain subscription credentials or user identifiers.
func SafeError(value string) string {
	value = proxyURI.ReplaceAllString(value, "proxy://<redacted>")
	value = httpURL.ReplaceAllString(value, "https://<redacted>")
	value = jsonSecret.ReplaceAllString(value, `"credential":"<redacted>"`)
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, value)
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > maxErrorRunes {
		runes = runes[:maxErrorRunes]
	}
	for len(runes) > 0 && len(string(runes)) > maxErrorBytes {
		runes = runes[:len(runes)-1]
	}
	if len(runes) == 0 {
		return "unknown SB core error"
	}
	return string(runes)
}
