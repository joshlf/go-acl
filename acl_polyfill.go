// +build darwin

package acl

import (
	"fmt"
	"os/exec"
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

func getImpl(path string, dfault bool) (ACL, error) {
	return ACL{}, syscall.ENOTSUP
}

func setImpl(path string, acl ACL, dfault bool) error {
	var cmd *exec.Cmd
	if dfault {
		cmd = exec.Command("setfacl", "--default", "--set", acl.String(), path)
	} else {
		cmd = exec.Command("setfacl", "--set", acl.String(), path)
	}
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("run setfacl: %v", err)
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
