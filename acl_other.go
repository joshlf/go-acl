// +build !linux

package acl

import (
	"syscall"
)

func get(path string) (ACL, error) {
	return nil, syscall.ENOTSUP
}

func getDefault(path string) (ACL, error) {
	return nil, syscall.ENOTSUP
}

func set(path string, acl ACL) error {
	return nil, syscall.ENOTSUP
}

func setDefault(path string, acl ACL) error {
	return nil, syscall.ENOTSUP
}
