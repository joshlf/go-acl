// NOTE: The library implemented in src/go-grp-unix.c
// is technically compatible with any Unix system
// (other than FreeBSD, although that's an easy fix);
// however, there's no point building for systems
// that can't use this library anyway (because there's
// no libacl linking support), so for the time being
// this file only compiles on Linux.

package acl

/*
	TODO:
	  - Using cgo to get the group name is a horrible
	    thing to have to do; hopefully a later release
	    will add this functionality to os/user
*/

// #include "include/go-grp-unix.h"
// #include "include/go-acl.h"
// #cgo LDFLAGS: -lgogrpunix
//
// #define LUINT unsigned long
import "C"

import (
	"os/user"
	"strconv"
	"unsafe"
)

func init() {
	formatQualifier = func(q string, tag Tag) string {
		switch tag {
		case TagUser:
			usr, err := user.LookupId(q)
			if err != nil {
				return q
			}
			return usr.Username
		case TagGroup:
			gid, err := strconv.ParseUint(q, 10, 64)
			if err != nil {
				return q
			}
			name := C.go_get_groupname(C.LUINT(gid))
			if name == nil {
				return q
			}
			defer C.go_free(unsafe.Pointer(name))
			return C.GoString(name)
		default:
			return q
		}
	}
}
