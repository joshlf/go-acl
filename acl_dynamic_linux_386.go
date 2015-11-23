// +build acl_link_dynamic

package acl

// #cgo LDFLAGS: -L${SRCDIR}/lib/linux/386/dynamic ${SRCDIR}/lib/linux/386/dynamic/libacl.so ${SRCDIR}/lib/linux/386/dynamic/libattr.so -lgoacl
import "C"
