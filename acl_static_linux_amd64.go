// +build !acl_link_dynamic

package acl

// #cgo LDFLAGS: -L${SRCDIR}/lib/linux/amd64/static -lgoacl
import "C"
