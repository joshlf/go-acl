// +build cgo

package acl

import (
	"C"
	"unsafe"
)

// ci == check int; calls panic(err)
// if code < 0
func ci(code C.int, err error) {
	if code < 0 {
		panic(err)
	}
}

// cp == check ptr; calls panic(err)
// if ptr == nil
func cp(ptr unsafe.Pointer, err error) {
	if ptr == nil {
		panic(err)
	}
}
