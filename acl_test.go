package acl

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func mustMakeTempFile(t *testing.T) string {
	f, err := ioutil.TempFile("", "acl")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	return f.Name()
}

func mustNotError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestGet(t *testing.T) {
	f := mustMakeTempFile(t)
	defer os.Remove(f)
	_, err := Get(f)
	mustNotError(t, err)
}

func TestSet(t *testing.T) {
	f := mustMakeTempFile(t)
	defer os.Remove(f)
	acl, err := Get(f)
	mustNotError(t, err)
	for i := range acl {
		acl[i].Perms = (^acl[i].Perms) & 0x7 // Flip the rwx bits
	}
	err = Set(f, acl)
	mustNotError(t, err)
	acl2, err := Get(f)
	mustNotError(t, err)
	if !reflect.DeepEqual(acl, acl2) {
		t.Errorf("unexpected ACL: want %v; got %v", acl, acl2)
	}
}

var (
	userObj  = Entry{Tag: TagUserObj}
	groupObj = Entry{Tag: TagGroupObj}
	other    = Entry{Tag: TagOther}
	user     = Entry{Tag: TagUser}
	group    = Entry{Tag: TagGroup}
	mask     = Entry{Tag: TagMask}
)

var validACLs = []ACL{
	{userObj, groupObj, other},
	{userObj, groupObj, other, user, mask},
	{userObj, groupObj, other, group, mask},
	{userObj, groupObj, other, user, group, mask},
	{userObj, groupObj, other, user, {Tag: TagUser, Qualifier: " "}, group, {Tag: TagGroup, Qualifier: " "}, mask},
}

var invalidACLs = []ACL{
	{},                  // No user, group, or other entries
	{userObj},           // No group or other entries
	{groupObj},          // No user or other entries
	{other},             // No user or group entries
	{userObj, groupObj}, // No other entry
	{userObj, other},    // No group entry
	{groupObj, other},   // No user entry

	{userObj, groupObj, other, {}},                 // Invalid tag type
	{userObj, groupObj, other, user},               // No mask
	{userObj, groupObj, other, group},              // No mask
	{userObj, groupObj, other, user, user, mask},   // Duplicate user qualifiers
	{userObj, groupObj, other, group, group, mask}, // Duplicate group qualifiers
	{userObj, groupObj, other, user, mask, mask},   // Duplicate mask entries
}

func TestIsValid(t *testing.T) {
	f := mustMakeTempFile(t)
	defer os.Remove(f)
	acl, err := Get(f)
	mustNotError(t, err)
	if !acl.IsValid() {
		t.Errorf("ACL reported invalid: %v", acl)
	}
	for _, v := range validACLs {
		if !v.IsValid() {
			t.Errorf("ACL reported invalid: %v", v)
		}
	}
	for _, i := range invalidACLs {
		if i.IsValid() {
			t.Errorf("ACL reported valid: %v", i)
		}
	}
}

func TestUnix(t *testing.T) {
	aclFromUnix := func(user, group, other os.FileMode) ACL {
		return ACL{
			{Tag: TagUserObj, Perms: user},
			{Tag: TagGroupObj, Perms: group},
			{Tag: TagOther, Perms: other},
		}
	}
	// Run through every possible unix permissions bitmask
	// and make sure it is generated with ToUnix and its
	// accompanying ACL is generated with FromUnix.
	for user := os.FileMode(0); user < 8; user++ {
		for group := os.FileMode(0); group < 8; group++ {
			for other := os.FileMode(0); other < 8; other++ {
				perms := (user << 6) | (group << 3) | other
				acl := aclFromUnix(user, group, other)
				permstmp := ToUnix(acl)
				// Add in extra high bits to make sure
				// we're only considering permissions bits
				max := ^os.FileMode(0)
				acltmp := FromUnix(perms | max<<9)
				if permstmp != perms {
					t.Errorf("unexpected perms: want %v; got %v; acl: %v", perms, permstmp, acl)
				}
				if !reflect.DeepEqual(acltmp, acl) {
					t.Errorf("unexpected acl: want %v; got %v; perms: %v", acl, acltmp, perms)
				}
			}
		}
	}
}

func ExamplePrint() {
	acl := ACL{
		{Tag: TagUserObj, Perms: 7},
		{Tag: TagGroupObj, Perms: 6},
		{Tag: TagOther, Perms: 5},
		{Tag: TagUser, Qualifier: "1", Perms: 4},
		{Tag: TagUser, Qualifier: "2", Perms: 3},
		{Tag: TagUser, Qualifier: "3", Perms: 2},
		{Tag: TagGroup, Qualifier: "4", Perms: 1},
		{Tag: TagGroup, Qualifier: "5", Perms: 0},
		{Tag: TagMask, Perms: 5},
	}
	fmt.Println(acl)
	fmt.Println(acl.StringLong())

	// Output: u::rwx,g::rw-,o::r-x,u:1:r--,u:2:-wx,u:3:-w-,g:4:--x,g:5:---,m::r-x
	// user::rwx
	// group::rw-          #effective:r--
	// other::r-x
	// user:1:r--
	// user:2:-wx          #effective:--x
	// user:3:-w-          #effective:---
	// group:4:--x
	// group:5:---
	// mask::r-x
}
