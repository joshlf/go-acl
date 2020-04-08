// Copyright 2020 the authors.
//
// Licensed under the Apache License, Version 2.0 (the LICENSE-APACHE file) or
// the MIT license (the LICENSE-MIT file) at your option. This file may not be
// copied, modified, or distributed except according to those terms.

package acl

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/joshlf/testutil"
)

func TestGet(t *testing.T) {
	f := testutil.MustTempFile(t, "", "acl").Name()
	defer os.Remove(f)
	_, err := Get(f)
	testutil.Must(t, err)

	d := testutil.MustTempDir(t, "", "acl")
	defer os.Remove(d)
	_, err = GetDefault(d)
	testutil.Must(t, err)
}

func TestSet(t *testing.T) {
	/*
		Access ACL
	*/
	f := testutil.MustTempFile(t, "", "acl").Name()
	defer os.Remove(f)
	acl, err := Get(f)
	testutil.Must(t, err)
	for i := range acl {
		acl[i].Perms = (^acl[i].Perms) & 0x7 // Flip the rwx bits
	}
	err = Set(f, acl)
	testutil.Must(t, err)
	acl2, err := Get(f)
	testutil.Must(t, err)
	if !reflect.DeepEqual(acl, acl2) {
		t.Errorf("unexpected ACL: want %v; got %v", acl, acl2)
	}

	/*
		Default ACL
	*/
	d := testutil.MustTempDir(t, "", "acl")
	defer os.Remove(d)
	// reuse the acl from above since we know it's valid
	err = SetDefault(d, acl)
	testutil.Must(t, err)
	acl2, err = GetDefault(d)
	testutil.Must(t, err)
	if !reflect.DeepEqual(acl, acl2) {
		t.Errorf("unexpected default ACL: want %v; got %v", acl, acl2)
	}
}

func TestAdd(t *testing.T) {
	f := testutil.MustTempFile(t, "", "acl").Name()
	defer os.Remove(f)

	base := ACL{
		{TagUserObj, "", 7},
		{TagGroupObj, "", 0},
		{TagOther, "", 0},
	}

	testCases := []struct {
		Before ACL
		Add    []Entry
		Afer   ACL
	}{
		// Make sure mask is generated
		{
			base,
			[]Entry{{TagUser, "0", 4}, {TagGroup, "0", 2}},
			append(ACL{{TagUser, "0", 4}, {TagGroup, "0", 2}, {TagMask, "", 6}}, base...),
		},
		// Make sure mask is not generated if a mask is supplied
		{
			base,
			[]Entry{{TagUser, "0", 4}, {TagGroup, "0", 2}, {TagMask, "", 1}},
			append(ACL{{TagUser, "0", 4}, {TagGroup, "0", 2}, {TagMask, "", 1}}, base...),
		},
		// Make sure the original mask is overridden
		{
			append(ACL{{TagMask, "", 7}}, base...),
			[]Entry{{TagUser, "0", 4}, {TagGroup, "0", 2}},
			append(ACL{{TagUser, "0", 4}, {TagGroup, "0", 2}, {TagMask, "", 6}}, base...),
		},
		// Make sure TagUser, TagGroup, or TagGroupObj in original is used
		// in calculating new mask
		{
			append(ACL{{TagUser, "0", 4}, {TagMask, "", 0}}, base...),
			[]Entry{{TagGroup, "0", 2}, {TagGroupObj, "", 1}},
			ACL{{TagUser, "0", 4}, {TagGroup, "0", 2}, {TagMask, "", 7},
				{TagUserObj, "", 7},
				{TagGroupObj, "", 1},
				{TagOther, "", 0}},
		},
		// Make sure TagUser or TagGroup in original is NOT used
		// in calculating new mask if it's overwritten
		{
			append(ACL{{TagUser, "0", 7}, {TagMask, "", 0}}, base...),
			[]Entry{{TagUser, "0", 4}, {TagGroup, "0", 2}},
			append(ACL{{TagUser, "0", 4}, {TagGroup, "0", 2}, {TagMask, "", 6}}, base...),
		},
	}

	for i, c := range testCases {
		err := Set(f, c.Before)
		testutil.Must(t, err)
		err = Add(f, c.Add...)
		testutil.Must(t, err)
		acl, err := Get(f)
		testutil.Must(t, err)

		m1 := make(map[Entry]bool)
		m2 := make(map[Entry]bool)
		for _, e := range acl {
			m1[e] = true
		}
		for _, e := range c.Afer {
			m2[e] = true
		}

		if !reflect.DeepEqual(m1, m2) {
			t.Errorf("case %v: unexpected ACL: want %v; got %v", i, c.Afer, acl)
		}
	}
}

func TestDefault(t *testing.T) {
	d := testutil.MustTempDir(t, "", "acl")
	defer os.RemoveAll(d)
	// Set default ACL to no permissions, which is pretty much
	// guaranteed not to be the system-wide default.
	// That way we know it's not a fluke if that's the ACL
	// on a newly-created file.
	dacl := ACL{Entry{Tag: TagUserObj}, Entry{Tag: TagUser, Qualifier: "0"},
		Entry{Tag: TagGroupObj}, Entry{Tag: TagGroup, Qualifier: "0"},
		Entry{Tag: TagMask}, Entry{Tag: TagOther}}
	err := SetDefault(d, dacl)
	testutil.Must(t, err)

	_, err = os.Create(filepath.Join(d, "file"))
	testutil.Must(t, err)
	acl, err := Get(filepath.Join(d, "file"))
	testutil.Must(t, err)
	if !reflect.DeepEqual(dacl, acl) {
		t.Errorf("access ACL does not match parent's default ACL: got %v; want %v",
			acl, dacl)
	}

	err = os.Mkdir(filepath.Join(d, "dir"), 0666)
	testutil.Must(t, err)
	dacl2, err := GetDefault(filepath.Join(d, "dir"))
	testutil.Must(t, err)
	if !reflect.DeepEqual(dacl, dacl2) {
		t.Errorf("default ACL does not match parent's default ACL: got %v; want %v",
			dacl2, dacl)
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
	f := testutil.MustTempFile(t, "", "acl").Name()
	defer os.Remove(f)
	acl, err := Get(f)
	testutil.Must(t, err)
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

func ExampleString() {
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
