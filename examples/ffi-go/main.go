package main

import (
	"fmt"
)

/*
#cgo LDFLAGS: -L./lib -lbip322_simple
#include "./bip322_simple.h"
#include <stdlib.h>
*/
import "C"

func main() {
	message := C.CString("test")
	//defer C.free(unsafe.Pointer(message))

	wif := C.CString("L3gn3CheHVnEJHApMjb6BuKdc45LzqChEebLMQaMh3V7cMh6qsaM")
	//defer C.free(unsafe.Pointer(wif))

	result := C.GoString(C.signature_with_wif_segwit(message, wif))
	fmt.Println("Result:", result)
}
