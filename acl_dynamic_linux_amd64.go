// +build acl_link_dynamic

package acl

// #cgo LDFLAGS: -L${SRCDIR}/lib/linux/dynamic -lacl
import "C"
