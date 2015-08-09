// Package acl implements POSIX.1e-compliant
// manipulation of access control lists (ACLs).
// See the acl manpage for details: http://linux.die.net/man/5/acl
package acl

// #include "include/linux/sys/acl.h"
// #include "include/linux/acl/libacl.h"
// #include <stdlib.h>
// #cgo LDFLAGS: -L${SRCDIR}/lib/linux -lacl
// #cgo CFLAGS: -I${SRCDIR}/include/linux
//
// #define ID_T_BITSIZE sizeof(id_t) * 8
import "C"

import (
	"fmt"
	"strconv"
	"syscall"
	"unsafe"
)

/*
	Note on errno: While cgo can automatically check
	errno and generate native Go errors, some library
	calls leave errno set but return non-error return
	codes. Thus, whenever returns need to be checked,
	the check should be performed as it would in C -
	by first checking the actual return value, and only
	using the error if the return value indicates error
	(ie, < 0 for signed values and NULL/nil for pointers).

	TODO:
		- Make ACL's String method use Posix short text
		  form.
*/

type tag C.acl_tag_t

const (
	tagUndefined Tag = C.ACL_UNDEFINED_TAG
	tagUserObj       = C.ACL_USER_OBJ  // Permissions of the file owner
	tagUser          = C.ACL_USER      // Permissions of a specified user
	tagGroupObj      = C.ACL_GROUP_OBJ // Permissions of the file group
	tagGroup         = C.ACL_GROUP     // Permissions of a specified group
	tagMask          = C.ACL_MASK      // Maximum allowed access rights of any entry
	tagOther         = C.ACL_OTHER     // Permissions of a process not matching any other entry
)

func aclCToGo(cacl C.acl_t) (ACL, error) {
	acl := make(ACL, 0)
	for {
		var centry C.acl_entry_t
		code, err := C.acl_get_entry(cacl, C.ACL_NEXT_ENTRY, &centry)
		// C.acl_get_entry returns 1 on success,
		// 0 when the list is exhausted, and < 0
		// on error
		if code == 0 {
			break
		} else if code < 0 {
			return nil, err
		}
		entry, err := entryCToGo(centry)
		if err != nil {
			return nil, err
		}
		acl = append(acl, entry)
	}
	return acl, nil
}

func entryCToGo(centry C.acl_entry_t) (entry Entry, err error) {
	defer func() {
		r := recover()
		if e, ok := r.(syscall.Errno); ok {
			entry = Entry{}
			err = e
		}
	}()

	var tag C.acl_tag_t
	ci(aclGetTagType(centry, &tag))
	entry.Tag = Tag(tag)

	var cperms C.acl_permset_t
	ci(aclGetPermset(centry, &cperms))
	code, err := aclGetPerm(cperms, C.ACL_READ)
	ci(code, err)
	if code > 0 {
		entry.Perms |= 4
	}
	code, err = aclGetPerm(cperms, C.ACL_WRITE)
	ci(code, err)
	if code > 0 {
		entry.Perms |= 2
	}
	code, err = aclGetPerm(cperms, C.ACL_EXECUTE)
	ci(code, err)
	if code > 0 {
		entry.Perms |= 1
	}

	if entry.Tag == TagUser || entry.Tag == TagGroup {
		var id C.id_t
		id_ptr, err := C.acl_get_qualifier(centry)
		if id_ptr == nil {
			return Entry{}, err
		}
		id = *(*C.id_t)(id_ptr)
		entry.Qualifier = fmt.Sprint(id)
	}

	return entry, nil
}

// if err == nil, all memory will
// be freed, and cacl will be nil
func aclGoToC(acl ACL) (cacl C.acl_t, err error) {
	// C.acl_init takes a prediction of
	// how many entries there will be
	cacl, err = C.acl_init(C.int(len(acl)))
	if cacl == nil {
		return
	}
	defer func() {
		if err != nil {
			C.acl_free(unsafe.Pointer(cacl))
			cacl = nil
		}
	}()
	for _, entry := range acl {
		err = addEntryGoToC(entry, cacl)
		if err != nil {
			return
		}
	}
	return
}

// addEntryGoToC will not free any memory,
// even if there is an error. However, any
// allocated memory should be associated
// with cacl, so as long as cacl is freed
// regardless of this function's error value,
// no memory should be leaked.
func addEntryGoToC(entry Entry, cacl C.acl_t) (err error) {
	defer func() {
		r := recover()
		if e, ok := r.(syscall.Errno); ok {
			err = e
		}
	}()

	var centry C.acl_entry_t
	ci(aclCreateEntry(&cacl, &centry))
	ci(aclSetTagType(centry, C.acl_tag_t(entry.Tag)))
	var perms C.acl_permset_t
	ci(aclGetPermset(centry, &perms))
	if entry.Perms&4 != 0 {
		ci(aclAddPerm(perms, C.ACL_READ))
	}
	if entry.Perms&2 != 0 {
		ci(aclAddPerm(perms, C.ACL_WRITE))
	}
	if entry.Perms&1 != 0 {
		ci(aclAddPerm(perms, C.ACL_EXECUTE))
	}

	if entry.Tag == TagUser || entry.Tag == TagGroup {
		n, err := strconv.ParseUint(entry.Qualifier, 10, C.ID_T_BITSIZE)
		if err != nil {
			return fmt.Errorf("parse qualifier: %v", err)
		}
		id := C.id_t(n)
		ci(aclSetQualifier(centry, unsafe.Pointer(&id)))
	}
	return nil
}

func getImpl(path string, typ C.acl_type_t) (ACL, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	cacl, err := C.acl_get_file(cpath, typ)
	if cacl == nil {
		return nil, fmt.Errorf("get acls on %v: %v", path, err)
	}
	defer C.acl_free(unsafe.Pointer(cacl))
	acl, err := aclCToGo(cacl)
	if err != nil {
		return nil, fmt.Errorf("get acls on %v: %v", path, err)
	}
	return acl, nil
}

func setImpl(path string, acl ACL, typ C.acl_type_t) error {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	cacl, err := aclGoToC(acl)
	if err != nil {
		return fmt.Errorf("set acls on %v: %v", path, err)
	}
	defer C.acl_free(unsafe.Pointer(cacl))
	code, err := C.acl_set_file(cpath, typ, cacl)
	if code < 0 {
		return fmt.Errorf("set acls on %v: %v", path, err)
	}
	return nil
}

func get(path string) (ACL, error) {
	return getImpl(path, C.ACL_TYPE_ACCESS)
}

func getDefault(path string) (ACL, error) {
	return getImpl(path, C.ACL_TYPE_DEFAULT)
}

func set(path string, acl ACL) error {
	return setImpl(path, acl, C.ACL_TYPE_ACCESS)
}

func setDefault(path string, acl ACL) error {
	return setImpl(path, acl, C.ACL_TYPE_DEFAULT)
}

// cgo calls can return one or two values
// depending on context. When used as
// arguments to function calls, they return
// one. We explicitly want them to return
// two when used in calls to ci or cp.

func aclGetTagType(entry C.acl_entry_t, tag *C.acl_tag_t) (C.int, error) {
	code, err := C.acl_get_tag_type(entry, tag)
	return code, err
}

func aclSetTagType(entry C.acl_entry_t, tag C.acl_tag_t) (C.int, error) {
	code, err := C.acl_set_tag_type(entry, tag)
	return code, err
}

func aclGetPermset(entry C.acl_entry_t, perms *C.acl_permset_t) (C.int, error) {
	code, err := C.acl_get_permset(entry, perms)
	return code, err
}

func aclGetPerm(perms C.acl_permset_t, perm C.acl_perm_t) (C.int, error) {
	code, err := C.acl_get_perm(perms, perm)
	return code, err
}

func aclAddPerm(perms C.acl_permset_t, perm C.acl_perm_t) (C.int, error) {
	code, err := C.acl_add_perm(perms, perm)
	return code, err
}

func aclCreateEntry(acl *C.acl_t, entry *C.acl_entry_t) (C.int, error) {
	code, err := C.acl_create_entry(acl, entry)
	return code, err
}

func aclSetQualifier(entry C.acl_entry_t, qualifier unsafe.Pointer) (C.int, error) {
	code, err := C.acl_set_qualifier(entry, qualifier)
	return code, err
}
