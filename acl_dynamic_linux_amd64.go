// +build acl_link_dynamic

package acl

// #cgo LDFLAGS: -L${SRCDIR}/lib/linux/amd64/dynamic ${SRCDIR}/lib/linux/amd64/dynamic/libacl.so ${SRCDIR}/lib/linux/amd64/dynamic/libattr.so -lgoacl
import "C"
