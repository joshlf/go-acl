// +build !acl_link_dynamic

package acl

// #cgo LDFLAGS: -L${SRCDIR}/lib/linux/386/static -lgoacl
import "C"
