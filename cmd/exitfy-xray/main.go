package main

/*
#include <stdlib.h>
*/
import "C"

import "github.com/kvuco/exitfy-cores/internal/bridge"

//export StartCore
func StartCore(configJSON *C.char) *C.char {
	if configJSON == nil {
		return C.CString("empty Xray configuration")
	}
	if err := bridge.Start(C.GoString(configJSON)); err != nil {
		return C.CString(bridge.SafeError(err.Error()))
	}
	return nil
}

//export StopCore
func StopCore() {
	_ = bridge.Stop()
}

func main() {}
