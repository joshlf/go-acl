// +build !acl_link_dynamic

package acl

// #cgo LDFLAGS: -L${SRCDIR}/lib/linux/static -lacl
import "C"
