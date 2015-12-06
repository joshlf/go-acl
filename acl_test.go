package acl

import (
	"fmt"
	"io/ioutil"
	"math/rand"
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
	usr      = Entry{Tag: TagUser} // Don't collide with os/user (imported by other files)
	group    = Entry{Tag: TagGroup}
	mask     = Entry{Tag: TagMask}
)

var validACLs = []ACL{
	{userObj, groupObj, other},
	{userObj, groupObj, other, usr, mask},
	{userObj, groupObj, other, group, mask},
	{userObj, groupObj, other, usr, group, mask},
	{userObj, groupObj, other, usr, {Tag: TagUser, Qualifier: " "}, group, {Tag: TagGroup, Qualifier: " "}, mask},
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
	{userObj, groupObj, other, usr},                // No mask
	{userObj, groupObj, other, group},              // No mask
	{userObj, groupObj, other, usr, usr, mask},     // Duplicate user qualifiers
	{userObj, groupObj, other, group, group, mask}, // Duplicate group qualifiers
	{userObj, groupObj, other, usr, mask, mask},    // Duplicate mask entries
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
	rand.Seed(1676218289)

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

	// Test to make sure that ToUnix can handle ACLs where
	// the entries are in any order and contain other entries
	// (besides those of tag UserObj, GroupObj, and Other)

	// Now, aclFromUnix will randomly generate an ACL with
	// the entries for UserObj, GroupObj, and Other having
	// the given permissions, but in a random order and with
	// entries of other tag types interspersed
	aclFromUnix = func(user, group, other os.FileMode) ACL {
		var otherTagTypes = []Tag{TagUser, TagGroup, TagMask}
		extraEntries := int(rand.ExpFloat64())

		// First, make an ACL that starts with the entries
		// we want and then contains random other entries
		a := ACL{
			{Tag: TagUserObj, Perms: user},
			{Tag: TagGroupObj, Perms: group},
			{Tag: TagOther, Perms: other},
		}
		for i := 0; i < extraEntries; i++ {
			tag := otherTagTypes[rand.Int()%len(otherTagTypes)]
			a = append(a, Entry{Tag: tag, Perms: os.FileMode(rand.Uint32()) & 7})
		}

		// Now permute them in a random order
		order := rand.Perm(len(a))
		b := make(ACL, len(a))
		for i := range b {
			b[i] = a[order[i]]
		}
		return b
	}

	const rounds = 100

	// Run through every possible unix permissions bitmask
	// and make sure it is generated with ToUnix and its
	// accompanying ACL is generated with FromUnix.
	for user := os.FileMode(0); user < 8; user++ {
		for group := os.FileMode(0); group < 8; group++ {
			for other := os.FileMode(0); other < 8; other++ {
				perms := (user << 6) | (group << 3) | other
				for i := 0; i < rounds; i++ {
					acl := aclFromUnix(user, group, other)
					permstmp := ToUnix(acl)
					if permstmp != perms {
						t.Errorf("unexpected perms: want %v; got %v; acl: %v", perms, permstmp, acl)
					}
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
		// It'd be nice to use different UIDs here, but root
		// is the only user whose UID is the same on all Unices
		{Tag: TagUser, Qualifier: "0", Perms: 4},
		{Tag: TagUser, Qualifier: "0", Perms: 3},
		{Tag: TagGroup, Qualifier: "0", Perms: 2},
		{Tag: TagMask, Perms: 2},
	}
	fmt.Println(acl)
	fmt.Println(acl.StringLong())

	// Output: u::rwx,g::rw-,o::r-x,u:root:r--,u:root:-wx,g:root:-w-,m::-w-
	// user::rwx
	// group::rw-          #effective:-w-
	// other::r-x
	// user:root:r--       #effective:---
	// user:root:-wx       #effective:-w-
	// group:root:-w-
	// mask::-w-
}
