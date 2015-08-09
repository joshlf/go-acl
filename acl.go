// Package acl implements POSIX.1e-compliant
// manipulation of access control lists (ACLs).
// See the acl manpage for details: http://linux.die.net/man/5/acl
package acl

import (
	"C"
	"fmt"
	"os"
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

type Tag tag

const (
	TagUndefined Tag = tagUndefined
	TagUserObj       = tagUserObj  // Permissions of the file owner
	TagUser          = tagUser     // Permissions of a specified user
	TagGroupObj      = tagGroupObj // Permissions of the file group
	TagGroup         = tagGroup    // Permissions of a specified group
	TagMask          = tagMask     // Maximum allowed access rights of any entry
	TagOther         = tagOther    // Permissions of a process not matching any other entry
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
		return fmt.Sprintf("UnknownTag(%v)", tag(t))
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
	Perms     os.FileMode
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
		toPrint = entry{e.Tag, e.Qualifier, aclPerm(e.Perms)}
	} else {
		type entry struct {
			Tag  Tag
			Perm aclPerm
		}
		toPrint = entry{e.Tag, aclPerm(e.Perms)}
	}
	return fmt.Sprint(toPrint)
}

func Get(path string) (ACL, error) {
	return get(path)
}

func GetDefault(path string) (ACL, error) {
	return getDefault(path)
}

func Set(path string, acl ACL) error {
	return set(path, acl)
}

func SetDefault(path string, acl ACL) error {
	return setDefault(path, acl)
}

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
