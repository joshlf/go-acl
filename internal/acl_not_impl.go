// +build !linux

package internal

import (
	"syscall"
)

type tag int

const (
	// While these aren't actually meaningful,
	// we still want them to be distinct so they
	// don't compare as equal
	tagUndefined Tag = iota
	tagUserObj
	tagUser
	tagGroupObj
	tagGroup
	tagMask
	tagOther
)

func get(path string) (ACL, error) {
	return nil, syscall.ENOTSUP
}

func getDefault(path string) (ACL, error) {
	return nil, syscall.ENOTSUP
}

func set(path string, acl ACL) error {
	return syscall.ENOTSUP
}

func setDefault(path string, acl ACL) error {
	return syscall.ENOTSUP
}
