// +build !acl_link_dynamic

package internal

// #cgo LDFLAGS: -L${SRCDIR}/lib/linux/386/static -lgoacl
import "C"
