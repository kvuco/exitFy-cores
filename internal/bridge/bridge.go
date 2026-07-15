package bridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode"

	libxray "github.com/xtls/libxray"
)

const (
	maxConfigBytes = 16 << 20
	maxErrorRunes  = 1024
	maxErrorBytes  = 4096
)

var (
	proxyURI   = regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|hy2|hysteria2?|tuic)://\S+`)
	httpURL    = regexp.MustCompile(`(?i)https?://\S+`)
	jsonSecret = regexp.MustCompile(
		`(?i)"(?:password|passwd|token|secret|uuid|authorization|hwid|username|user|id)"\s*:\s*"[^"]*"`,
	)
)

var lifecycle struct {
	sync.Mutex
	running bool
}

type invokeRequest struct {
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type invokeResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// Start validates the untrusted configuration and starts exactly one Xray
// instance. Calls are serialized because libXray owns process-global state.
func Start(configJSON string) error {
	lifecycle.Lock()
	defer lifecycle.Unlock()

	configJSON = strings.TrimSpace(configJSON)
	if configJSON == "" {
		return errors.New("empty Xray configuration")
	}
	if len(configJSON) > maxConfigBytes {
		return fmt.Errorf("Xray configuration exceeds %d bytes", maxConfigBytes)
	}
	if lifecycle.running {
		return errors.New("Xray is already running")
	}

	var config map[string]json.RawMessage
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("invalid Xray configuration: %w", err)
	}
	if config == nil {
		return errors.New("invalid Xray configuration: root must be an object")
	}

	payload, err := json.Marshal(map[string]string{"configJSON": configJSON})
	if err != nil {
		return fmt.Errorf("encode Xray request: %w", err)
	}
	request, err := json.Marshal(invokeRequest{
		Method:  "runXrayFromJson",
		Payload: payload,
	})
	if err != nil {
		return fmt.Errorf("encode Xray request: %w", err)
	}

	if err := invoke(request); err != nil {
		return err
	}
	lifecycle.running = true
	return nil
}

// Stop is synchronized and idempotent.
func Stop() error {
	lifecycle.Lock()
	defer lifecycle.Unlock()

	if !lifecycle.running {
		return nil
	}
	request, err := json.Marshal(invokeRequest{Method: "stopXray"})
	if err != nil {
		return fmt.Errorf("encode Xray stop request: %w", err)
	}
	if err := invoke(request); err != nil {
		return err
	}
	lifecycle.running = false
	return nil
}

func IsRunning() bool {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	return lifecycle.running
}

func invoke(request []byte) error {
	raw := libxray.Invoke(string(request))
	var response invokeResponse
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		return fmt.Errorf("invalid libXray response: %w", err)
	}
	if !response.Success {
		if response.Error == "" {
			response.Error = "libXray rejected the request"
		}
		return errors.New(SafeError(response.Error))
	}
	return nil
}

// SafeError makes the exported error bounded and safe for Java logs/UI.
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
		return "unknown Xray error"
	}
	return string(runes)
}
