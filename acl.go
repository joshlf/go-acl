// Package acl implements POSIX.1e-compliant
// manipulation of access control lists (ACLs).
// See the acl manpage for details: http://linux.die.net/man/5/acl
package main

// #include <sys/types.h>
// #include <sys/acl.h>
// #include <stdlib.h>
// #cgo linux LDFLAGS: -lacl
//
// #define ID_T_BITSIZE sizeof(id_t) * 8
import "C"

import (
	"fmt"
	"os"
	"strconv"
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

type ACL []Entry

type Tag C.acl_tag_t

const (
	TagUndefined Tag = C.ACL_UNDEFINED_TAG
	TagUserObj       = C.ACL_USER_OBJ  // Permissions of the file owner
	TagUser          = C.ACL_USER      // Permissions of a specified user
	TagGroupObj      = C.ACL_GROUP_OBJ // Permissions of the file group
	TagGroup         = C.ACL_GROUP     // Permissions of a specified group
	TagMask          = C.ACL_MASK      // Maximum allowed access rights of any entry
	TagOther         = C.ACL_OTHER     // Permissions of a process not matching any other entry
)

func (t Tag) String() string {
	switch t {
	case TagUndefined:
		return "TagUndefined"
	case TagUserObj:
		return "TagUserObj"
	case TagUser:
		return "TagUser"
	case TagGroupObj:
		return "TagGroupObj"
	case TagGroup:
		return "TagGroup"
	case TagMask:
		return "TagMask"
	case TagOther:
		return "TagOther"
	default:
		return fmt.Sprintf("UnknownTag(%v)", C.acl_tag_t(t))
	}
}

type Entry struct {
	Tag Tag

	// TODO(synful): are we sure we want to use a string
	// for this? I'm going off of os/user.User, but maybe
	// we just want an integer type? I suppose a string
	// is more cross-platform (that is, assuming we come
	// across a platform which supports ACLs but uses
	// non-numeric UIDs and GIDs?)

	// The Qualifier specifies what entity (user or group)
	// this entry applies to. If the Tag is TagUser, it is
	// a UID; if the Tag is TagGroup, it is a GID; and otherwise
	// the field is ignored.
	Qualifier string
	Perm      os.FileMode
}

// Used for pretty-printing
type aclPerm os.FileMode

func (a aclPerm) String() string {
	var buf [3]byte
	const rwx = "rwx"
	for i := 2; i >= 0; i-- {
		if a&1 != 0 {
			buf[i] = rwx[i]
		} else {
			buf[i] = '-'
		}
		a >>= 1
	}
	return string(buf[:])
}

func (e Entry) String() string {
	var toPrint interface{}
	if e.Tag == TagUser || e.Tag == TagGroup {
		type entry struct {
			Tag       Tag
			Qualifier string
			Perm      aclPerm
		}
		toPrint = entry{e.Tag, e.Qualifier, aclPerm(e.Perm)}
	} else {
		type entry struct {
			Tag  Tag
			Perm aclPerm
		}
		toPrint = entry{e.Tag, aclPerm(e.Perm)}
	}
	return fmt.Sprint(toPrint)
}

func entryCToGo(centry C.acl_entry_t) (Entry, error) {
	var entry Entry
	var tag C.acl_tag_t
	code, err := C.acl_get_tag_type(centry, &tag)
	if code < 0 {
		return Entry{}, err
	}
	entry.Tag = Tag(tag)

	var perms C.acl_permset_t
	code, err = C.acl_get_permset(centry, &perms)
	if code < 0 {
		return Entry{}, err
	}

	entry.Perm, err = permCToGo(perms)
	if err != nil {
		return Entry{}, err
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
func addEntryGoToC(entry Entry, cacl C.acl_t) error {
	var centry C.acl_entry_t
	code, err := C.acl_create_entry(&cacl, &centry)
	if code < 0 {
		return err
	}
	code, err = C.acl_set_tag_type(centry, C.acl_tag_t(entry.Tag))
	if code < 0 {
		return err
	}
	var perms C.acl_permset_t
	code, err = C.acl_get_permset(centry, &perms)
	if code < 0 {
		return err
	}
	if entry.Perm&4 != 0 {
		code, err = C.acl_add_perm(perms, C.ACL_READ)
		if code < 0 {
			return err
		}
	}
	if entry.Perm&2 != 0 {
		code, err = C.acl_add_perm(perms, C.ACL_WRITE)
		if code < 0 {
			return err
		}
	}
	if entry.Perm&1 != 0 {
		code, err = C.acl_add_perm(perms, C.ACL_EXECUTE)
		if code < 0 {
			return err
		}
	}

	if entry.Tag == TagUser || entry.Tag == TagGroup {
		n, err := strconv.ParseUint(entry.Qualifier, 10, C.ID_T_BITSIZE)
		if err != nil {
			return fmt.Errorf("parse qualifier: %v", err)
		}
		id := C.id_t(n)
		code, err = C.acl_set_qualifier(centry, unsafe.Pointer(&id))
		if code < 0 {
			return err
		}
	}
	return nil
}

func getFile(path string, typ C.acl_type_t) (ACL, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	cacl, err := C.acl_get_file(cpath, typ)
	defer C.acl_free(unsafe.Pointer(cacl))
	if cacl == nil {
		return nil, fmt.Errorf("get acls on %v: %v", path, err)
	}
	acl, err := aclCToGo(cacl)
	if err != nil {
		return nil, fmt.Errorf("get acls on %v: %v", path, err)
	}
	return acl, nil
}

func setFile(path string, acl ACL, typ C.acl_type_t) error {
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

func GetFile(path string) (ACL, error) {
	return getFile(path, C.ACL_TYPE_ACCESS)
}

func GetFileDefault(path string) (ACL, error) {
	return getFile(path, C.ACL_TYPE_DEFAULT)
}

func SetFile(path string, acl ACL) error {
	return setFile(path, acl, C.ACL_TYPE_ACCESS)
}

func SetFileDefault(path string, acl ACL) error {
	return setFile(path, acl, C.ACL_TYPE_DEFAULT)
}

func main() {
	acl, err := GetFile(os.Args[1])
	fmt.Println(acl, err)
	if err == nil {
		fmt.Println(SetFile(os.Args[2], acl))
	}
}
