/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

/*
#cgo LDFLAGS: -lursa
#include "ursa_cl.h"
#include <stdlib.h>
 */
import "C"
import (
	"fmt"
	"unsafe"
)

func NewNonce() (string, error) {
	var nonce unsafe.Pointer
	defer C.free(nonce)

	var d *C.char
	defer C.free(unsafe.Pointer(d))

	result := C.ursa_cl_new_nonce(&nonce)
	if result != 0 {
		return "", fmt.Errorf("failed to generate new nonce: (Ursa error code: [%v])", result)
	}

	errCode := C.ursa_cl_nonce_to_json(nonce, &d)
	if errCode != 0 {
		return "", fmt.Errorf("failed to convert nonce to json: (Ursa error code: [%v]", errCode)
	}

	return C.GoString(d), nil
}