package main

/*
#include <stddef.h>
#include <stdlib.h>

static size_t exitfy_bounded_strlen(const char *value, size_t limit) {
    size_t length = 0;
    if (value == NULL) return 0;
    while (length < limit && value[length] != '\0') length++;
    return length;
}
*/
import "C"

import "github.com/kvuco/exitfy-cores/singbox/internal/bridge"

//export StartCore
func StartCore(configJSON *C.char) *C.char {
	if configJSON == nil {
		return C.CString("empty SB core configuration")
	}
	length := C.exitfy_bounded_strlen(configJSON, C.size_t(bridge.MaxConfigBytes+1))
	if length > C.size_t(bridge.MaxConfigBytes) {
		return C.CString("SB core configuration exceeds 16777216 bytes")
	}
	value := C.GoStringN(configJSON, C.int(length))
	if err := bridge.Start(value); err != nil {
		return C.CString(bridge.SafeError(err.Error()))
	}
	return nil
}

//export StopCore
func StopCore() *C.char {
	if err := bridge.Stop(); err != nil {
		return C.CString(bridge.SafeError(err.Error()))
	}
	return nil
}

func main() {}
