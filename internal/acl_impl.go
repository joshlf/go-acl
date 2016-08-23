// +build linux

package internal

/*
	Note on errno: While cgo can automatically check
	errno and generate native Go errors, errno being
	set is not in and of itself an indication of an
	error (for example, it might have been set
	previously and not reset). Thus, whenever returns
	need to be checked, the check should be performed
	as it would in C - by first checking the actual
	return value, and only using the error if the
	return value indicates error (ie, < 0 for signed
	values and NULL/nil for pointers).
*/

// #include "include/go-acl.h"
//
// #define LUINT unsigned long
import "C"

import (
	"fmt"
	"os"
	"strconv"
	"unsafe"
)

type tag C.go_acl_tag_t

const (
	tagUserObj  = C.TAG_USER_OBJ
	tagUser     = C.TAG_USER
	tagGroupObj = C.TAG_GROUP_OBJ
	tagGroup    = C.TAG_GROUP
	tagMask     = C.TAG_MASK
	tagOther    = C.TAG_OTHER
)

func aclCToGo(cacl C.go_acl_t) ACL {
	acl := make(ACL, cacl.num_entries)
	for i := range acl {
		centry := C.go_acl_get_entry(cacl, C.int(i))
		acl[i].Tag = Tag(centry.tag)
		acl[i].Perms = os.FileMode(centry.perms)
		if acl[i].Tag == TagUser || acl[i].Tag == TagGroup {
			acl[i].Qualifier = fmt.Sprint(centry.qualifier)
		}
	}
	return acl
}

func aclGoToC(acl ACL) (C.go_acl_t, error) {
	cacl := C.go_acl_create(C.int(len(acl)))
	for i, e := range acl {
		var centry C.go_acl_entry_t
		centry.tag = C.go_acl_tag_t(e.Tag)
		centry.perms = C.int(e.Perms)
		if e.Tag == TagUser || e.Tag == TagGroup {
			n, err := strconv.ParseUint(e.Qualifier, 10, 64)
			if err != nil {
				C.go_acl_free(cacl)
				return C.go_acl_t(nil), fmt.Errorf("parse qualifier: %v", err)
			}
			centry.qualifier = C.LUINT(n)
		}
		C.go_acl_put_entry(cacl, C.int(i), centry)
	}
	return cacl, nil
}

func qualifierStringToInt(qualifier string) (C.LUINT, error) {
	n, err := strconv.ParseUint(qualifier, 10, 64)
	if err != nil {
		// it's not a UID; try looking it up
	}
	return C.LUINT(n), nil
}

func getImpl(path string, dfault bool) (ACL, error) {
	cpath := C.CString(path)
	defer C.go_free(unsafe.Pointer(cpath))
	var cacl C.go_acl_t
	var err error
	if dfault {
		cacl, err = C.go_acl_get_file_default(cpath)
	} else {
		cacl, err = C.go_acl_get_file(cpath)
	}
	if cacl == nil {
		return nil, fmt.Errorf("get acls on %v: %v", path, err)
	}
	defer C.go_acl_free(cacl)
	return aclCToGo(cacl), nil
}

func setImpl(path string, acl ACL, dfault bool) error {
	cpath := C.CString(path)
	defer C.go_free(unsafe.Pointer(cpath))
	cacl, err := aclGoToC(acl)
	if err != nil {
		return fmt.Errorf("set acls on %v: %v", path, err)
	}
	defer C.go_acl_free(cacl)
	var code C.int
	if dfault {
		code, err = C.go_acl_set_file_default(cpath, cacl)
	} else {
		code, err = C.go_acl_set_file(cpath, cacl)
	}
	if code < 0 {
		return fmt.Errorf("set acls on %v: %v", path, err)
	}
	return nil
}

func get(path string) (ACL, error) {
	return getImpl(path, false)
}

func getDefault(path string) (ACL, error) {
	return getImpl(path, true)
}

func set(path string, acl ACL) error {
	return setImpl(path, acl, false)
}

func setDefault(path string, acl ACL) error {
	return setImpl(path, acl, true)
}
