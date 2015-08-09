package main

// #include <acl/libacl.h>
import "C"

import (
	"os"
)

func permCToGo(cperm C.acl_permset_t) (os.FileMode, error) {
	var perm os.FileMode
	code, err := C.acl_get_perm(cperm, C.ACL_READ)
	if code < 0 {
		return perm, err
	}
	if code > 0 {
		perm |= 4
	}
	code, err = C.acl_get_perm(cperm, C.ACL_WRITE)
	if code < 0 {
		return perm, err
	}
	if code > 0 {
		perm |= 2
	}
	code, err = C.acl_get_perm(cperm, C.ACL_EXECUTE)
	if code < 0 {
		return perm, err
	}
	if code > 0 {
		perm |= 1
	}
	return perm, nil
}
