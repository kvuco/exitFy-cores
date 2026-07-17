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
	maxConfigBytes        = 16 << 20
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
	proxyURI       = regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|hy2|hysteria2?|tuic)://\S+`)
	httpURL        = regexp.MustCompile(`(?i)https?://\S+`)
	secretFieldKey = regexp.MustCompile(
		`(?i)\b(?:` + secretKeyPattern + `)["']?\s*[:=]\s*`,
	)
	invokeLibXray = libxray.Invoke
)

var lifecycle struct {
	sync.Mutex
	running      bool
	stopRequired bool
}

type invokeRequest struct {
	APIVersion int             `json:"apiVersion"`
	Method     string          `json:"method"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

type invokeResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// Start validates the untrusted configuration and starts exactly one Xray
// instance. Calls are serialized because libXray owns process-global state.
func Start(configJSON string) (err error) {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			err = recoveredError("Xray start panic", recovered)
		}
	}()

	configJSON = strings.TrimSpace(configJSON)
	if configJSON == "" {
		return errors.New("empty Xray configuration")
	}
	if len(configJSON) > maxConfigBytes {
		return fmt.Errorf("Xray configuration exceeds %d bytes", maxConfigBytes)
	}
	if lifecycle.running || lifecycle.stopRequired {
		return errors.New("Xray is already running or requires StopCore")
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
		APIVersion: 1,
		Method:     "runXrayFromJson",
		Payload:    payload,
	})
	if err != nil {
		return fmt.Errorf("encode Xray request: %w", err)
	}

	// Once libXray has received a start request, an invalid/truncated response
	// cannot prove that the process-global runtime stayed stopped. Keep the
	// adapter in a stop-required state so JNI's serialized cleanup always
	// reaches stopXray and a retry cannot create two instances.
	lifecycle.stopRequired = true
	if err := invoke(request); err != nil {
		return err
	}
	lifecycle.running = true
	return nil
}

// Stop is synchronized and idempotent.
func Stop() (err error) {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			err = recoveredError("Xray stop panic", recovered)
		}
	}()

	if !lifecycle.running && !lifecycle.stopRequired {
		return nil
	}
	// A panic or malformed libXray response cannot prove that the global
	// runtime stopped. Keep retry mandatory until a confirmed success.
	lifecycle.stopRequired = true
	request, err := json.Marshal(invokeRequest{APIVersion: 1, Method: "stopXray"})
	if err != nil {
		return fmt.Errorf("encode Xray stop request: %w", err)
	}
	if err := invoke(request); err != nil {
		return err
	}
	lifecycle.running = false
	lifecycle.stopRequired = false
	return nil
}

func recoveredError(prefix string, recovered any) error {
	return errors.New(SafeError(fmt.Sprintf("%s: %v", prefix, recovered)))
}

func IsRunning() bool {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	return lifecycle.running
}

func invoke(request []byte) error {
	raw := invokeLibXray(string(request))
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
		return "unknown Xray error"
	}
	return string(runes)
}

func boundedSanitizeInput(value string) string {
	if len(value) <= maxSanitizeInputBytes {
		return value
	}
	end := maxSanitizeInputBytes
	// End before a UTF-8 continuation byte. Invalid leading bytes remain safe:
	// the rune conversion below replaces them with U+FFFD.
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
