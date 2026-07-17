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
	MaxConfigBytes        = 16 << 20
	maxSanitizeInputBytes = 64 << 10
	maxErrorRunes         = 1024
	maxErrorBytes         = 4096
	secretKeyPattern      = `proxy-authorization|pre_shared_key|pre-shared-key|` +
		`private_key|private-key|obfs-password|obfs_password|authorization|` +
		`refresh_token|access_token|client_secret|auth_str|auth-str|` +
		`legacy_seed|legacy-seed|x-api-key|x_api_key|api-key|api_key|` +
		`password|passwd|username|encryption|headers|cookie|token|secret|` +
		`uuid|hwid|x-hwid|presharedkey|privatekey|pass|auth|obfs|psk|` +
		`seed|path|user|id`
)

var (
	proxyURI = regexp.MustCompile(
		`(?i)\b(?:vless|vmess|trojan|ss|hy2|hysteria2?|tuic)://\S+`,
	)
	httpURL        = regexp.MustCompile(`(?i)https?://\S+`)
	secretFieldKey = regexp.MustCompile(
		`(?i)\b(?:` + secretKeyPattern + `)["']?\s*[:=]\s*`,
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
	var candidate core
	var cancel context.CancelFunc
	lifecycle.Lock()
	defer lifecycle.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			if cancel != nil {
				cancel()
			}
			if candidate != nil {
				if closeError := closeCore(candidate); !isOnlyClosed(closeError) {
					lifecycle.instance = candidate
					lifecycle.cancel = cancel
					lifecycle.stopRequired = true
				}
			}
			err = recoveredError("SB core start panic", recovered)
		}
	}()

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

	runCtx, createdCancel := context.WithCancel(baseCtx)
	cancel = createdCancel

	candidate, err = newCore(runCtx, options)
	if err != nil {
		cancel()
		// A factory may return a partially constructed Box together with an
		// error. Treat ownership as transferred whenever candidate is non-nil:
		// either close it now or retain it for serialized StopCore retry.
		if candidate != nil {
			if closeError := closeCore(candidate); !isOnlyClosed(closeError) {
				lifecycle.instance = candidate
				lifecycle.cancel = cancel
				lifecycle.stopRequired = true
				return fmt.Errorf("create SB core: %w; cleanup: %v", err, closeError)
			}
		}
		return fmt.Errorf("create SB core: %w", err)
	}
	if err = candidate.Start(); err != nil {
		cancel()
		if closeError := closeCore(candidate); !isOnlyClosed(closeError) {
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
	defer func() {
		if recovered := recover(); recovered != nil {
			err = recoveredError("SB core stop panic", recovered)
		}
	}()

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
		if !isOnlyClosed(closeError) {
			return fmt.Errorf("stop SB core: %w", closeError)
		}
	}
	lifecycle.instance = nil
	lifecycle.cancel = nil
	lifecycle.stopRequired = false
	return nil
}

func recoveredError(prefix string, recovered any) error {
	return errors.New(SafeError(fmt.Sprintf("%s: %v", prefix, recovered)))
}

func IsRunning() bool {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	return lifecycle.instance != nil && !lifecycle.stopRequired
}

func isOnlyClosed(err error) bool {
	if err == nil {
		return true
	}
	if multiple, ok := err.(interface{ Unwrap() []error }); ok {
		children := multiple.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !isOnlyClosed(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		child := wrapped.Unwrap()
		return child != nil && isOnlyClosed(child)
	}
	return err == os.ErrClosed
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
	value = boundedSanitizeInput(value)
	value = proxyURI.ReplaceAllString(value, "proxy://<redacted>")
	value = httpURL.ReplaceAllString(value, "https://<redacted>")
	value = redactJSONSecrets(value)
	value = redactPlainSecrets(value)
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

func boundedSanitizeInput(value string) string {
	if len(value) <= maxSanitizeInputBytes {
		return value
	}
	end := maxSanitizeInputBytes
	for end > 0 && value[end]&0xc0 == 0x80 {
		end--
	}
	return value[:end]
}

func redactJSONSecrets(value string) string {
	var output strings.Builder
	cursor := 0
	index := 0
	changed := false
	for index < len(value) {
		if value[index] != '"' {
			index++
			continue
		}
		keyEnd := jsonStringEnd(value, index)
		if keyEnd < 0 {
			break
		}
		colon := skipJSONWhitespace(value, keyEnd+1)
		if colon >= len(value) || value[colon] != ':' {
			index = keyEnd + 1
			continue
		}
		key, valid := decodeJSONKey(value[index+1 : keyEnd])
		if !valid || !isSecretKey(key) {
			index = keyEnd + 1
			continue
		}
		valueStart := skipJSONWhitespace(value, colon+1)
		valueEnd := jsonSecretValueEnd(value, valueStart)
		if !changed {
			output.Grow(len(value))
			changed = true
		}
		output.WriteString(value[cursor:index])
		output.WriteString(`"credential":"<redacted>"`)
		cursor = valueEnd
		index = valueEnd
	}
	if !changed {
		return value
	}
	output.WriteString(value[cursor:])
	return output.String()
}

func jsonStringEnd(value string, quote int) int {
	for index := quote + 1; index < len(value); index++ {
		switch value[index] {
		case '\\':
			index++
		case '"':
			return index
		}
	}
	return -1
}

func skipJSONWhitespace(value string, start int) int {
	index := start
	if index < 0 {
		index = 0
	}
	for index < len(value) {
		switch value[index] {
		case ' ', '\t', '\r', '\n':
			index++
		default:
			return index
		}
	}
	return index
}

func decodeJSONKey(raw string) (string, bool) {
	if !strings.Contains(raw, `\`) {
		return raw, true
	}
	var output strings.Builder
	output.Grow(len(raw))
	for index := 0; index < len(raw); index++ {
		current := raw[index]
		if current != '\\' {
			output.WriteByte(current)
			continue
		}
		if index+1 >= len(raw) {
			return "", false
		}
		index++
		switch raw[index] {
		case '"', '\\', '/':
			output.WriteByte(raw[index])
		case 'b':
			output.WriteByte('\b')
		case 'f':
			output.WriteByte('\f')
		case 'n':
			output.WriteByte('\n')
		case 'r':
			output.WriteByte('\r')
		case 't':
			output.WriteByte('\t')
		case 'u':
			if index+4 >= len(raw) {
				return "", false
			}
			codepoint, valid := decodeHexQuad(raw[index+1 : index+5])
			if !valid {
				return "", false
			}
			index += 4
			if codepoint >= 0xd800 && codepoint <= 0xdbff {
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return "", false
				}
				low, lowValid := decodeHexQuad(raw[index+3 : index+7])
				if !lowValid || low < 0xdc00 || low > 0xdfff {
					return "", false
				}
				codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00)
				index += 6
			} else if codepoint >= 0xdc00 && codepoint <= 0xdfff {
				return "", false
			}
			output.WriteRune(rune(codepoint))
		default:
			return "", false
		}
	}
	return output.String(), true
}

func decodeHexQuad(value string) (uint32, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result uint32
	for index := 0; index < len(value); index++ {
		var digit byte
		switch current := value[index]; {
		case current >= '0' && current <= '9':
			digit = current - '0'
		case current >= 'a' && current <= 'f':
			digit = current - 'a' + 10
		case current >= 'A' && current <= 'F':
			digit = current - 'A' + 10
		default:
			return 0, false
		}
		result = result<<4 | uint32(digit)
	}
	return result, true
}

func isSecretKey(value string) bool {
	switch strings.ToLower(value) {
	case "password", "passwd", "pass", "token", "access_token", "refresh_token",
		"client_secret", "secret", "uuid", "proxy-authorization", "authorization",
		"auth_str", "auth-str", "auth", "obfs-password", "obfs_password", "obfs",
		"encryption", "private_key", "private-key", "privatekey", "pre_shared_key",
		"pre-shared-key", "presharedkey", "psk", "legacy_seed", "legacy-seed",
		"seed", "path", "headers", "cookie", "x-api-key", "x_api_key", "api-key",
		"api_key", "x-hwid", "hwid", "username", "user", "id":
		return true
	default:
		return false
	}
}

func redactPlainSecrets(value string) string {
	matches := secretFieldKey.FindAllStringIndex(value, -1)
	if len(matches) == 0 {
		return value
	}
	var output strings.Builder
	output.Grow(len(value))
	cursor := 0
	for _, match := range matches {
		if match[0] < cursor {
			continue
		}
		output.WriteString(value[cursor:match[0]])
		output.WriteString("credential=<redacted>")
		cursor = plainSecretValueEnd(value, match[1])
	}
	output.WriteString(value[cursor:])
	return output.String()
}

func plainSecretValueEnd(value string, start int) int {
	// An unstructured diagnostic has no grammar that can prove where a
	// credential ends.  Even a quoted value may be followed by attacker-owned
	// text.  Consume the remainder instead of trusting words such as `status=`
	// as a boundary and potentially exposing part of the secret.
	return len(value)
}

func jsonSecretValueEnd(value string, start int) int {
	if start >= len(value) {
		return len(value)
	}
	switch value[start] {
	case '"':
		escaped := false
		for index := start + 1; index < len(value); index++ {
			current := value[index]
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				return jsonObjectValueEnd(value, index+1)
			}
		}
		return len(value)
	case '{', '[':
		stack := []byte{matchingJSONCloser(value[start])}
		inString := false
		escaped := false
		for index := start + 1; index < len(value); index++ {
			current := value[index]
			if inString {
				if escaped {
					escaped = false
				} else if current == '\\' {
					escaped = true
				} else if current == '"' {
					inString = false
				}
				continue
			}
			switch current {
			case '"':
				inString = true
			case '{', '[':
				stack = append(stack, matchingJSONCloser(current))
			case '}', ']':
				if len(stack) == 0 || current != stack[len(stack)-1] {
					return len(value)
				}
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					return jsonObjectValueEnd(value, index+1)
				}
			}
		}
		return len(value)
	default:
		if end := jsonPrimitiveValueEnd(value, start); end >= 0 {
			return end
		}
		return plainSecretValueEnd(value, start)
	}
}

func jsonPrimitiveValueEnd(value string, start int) int {
	index := start
	for _, literal := range []string{"true", "false", "null"} {
		if strings.HasPrefix(value[start:], literal) {
			index = start + len(literal)
			return jsonObjectValueEnd(value, index)
		}
	}
	if index < len(value) && value[index] == '-' {
		index++
	}
	if index >= len(value) {
		return -1
	}
	if value[index] == '0' {
		index++
	} else if value[index] >= '1' && value[index] <= '9' {
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			index++
		}
	} else {
		return -1
	}
	if index < len(value) && value[index] == '.' {
		index++
		fractionStart := index
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			index++
		}
		if index == fractionStart {
			return -1
		}
	}
	if index < len(value) && (value[index] == 'e' || value[index] == 'E') {
		index++
		if index < len(value) && (value[index] == '+' || value[index] == '-') {
			index++
		}
		exponentStart := index
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			index++
		}
		if index == exponentStart {
			return -1
		}
	}
	return jsonObjectValueEnd(value, index)
}

func jsonObjectValueEnd(value string, tokenEnd int) int {
	index := tokenEnd
	for index < len(value) {
		switch value[index] {
		case ' ', '\t', '\r', '\n':
			index++
		default:
			if value[index] == ',' || value[index] == '}' {
				return tokenEnd
			}
			return len(value)
		}
	}
	return tokenEnd
}

func matchingJSONCloser(opener byte) byte {
	if opener == '{' {
		return '}'
	}
	return ']'
}
