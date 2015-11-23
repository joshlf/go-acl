CONTRIBUTING
============

Contributions are of course welcome - especially those that add support for other OSs/architectures! This document serves primarily to outline the layout of this package, as it's somewhat non-standard.

#Overview

This package is implemented primarily in C, with a small amount of Go code wrapping it. Everything is defined in `src/go-acl.h`, and all C implementations implement that interface. The interface itself is intended to be as cross-platform as possible - crucially, it includes *no* system header files (actually, no other header files of any kind). The C implementations of this interface - different implementations for different architectures - are compiled *by the developers* into `.a` files which are distributed as part of the code of this repository. End users of this package can rely on these `.a` files, which are all that are required (along with a few other dependencies which are also distributed with the repo) to build the package.

#Motivation

The motivation for this architecture is ease of use for the end-user. Since this package is not a highly-specialized package for some niche field, but rather a general-purpose utility package that could be used in many different applications, we want to make it as easy as possible for users to use it. In particular, compiling with this package should be as close in ease as possible to compiling a native Go package.

In particular, since `cgo` is used to interface with libacl, the obvious way of implementing the package (as simple libacl bindings; this was actually the architecture of the initial version of this package) presents a serious problem: any end-user wishing to cross-compile their project would need to have all appropriate system header files and library files installed. For example, a Debian user on a 64-bit architecture trying to compile their project for 32-bit Linux would need the packages `libc6-dev-i386` and `libacl-dev`. Reliance on these sorts of specialized external dependencies makes it harder to use the package, and goes against the Go philosophy.

#Architecture

There are a few key components of the architecture of this package:

* Most importantly, any system-dependent code is implemented in C. This means that it can be compiled by the package authors into libraries which are in turn distributed with the package; end users only use these pre-compiled files. In practice, most logic is system-dependent, so the code in Go amounts to a simple shim layer.
* In particular, `include/go-acl.h` includes *no* other header files. Additionally, it provides a wrapper to `stdlib.h`'s `free` (`go_free`) so that Go code can avoid including `stdlib.h` (freeing is necessary when using cgo's `C.Cstring`).
* In order to include all dependencies, this repository includes all of the `.o` files which are wrapped by `libacl.a`. When producing `libgoacl.a`, the library file that cgo uses, all of the `.o` files from libacl are included. When producing `libgoacl.a` for dynamic linking (that is, programs which wish to dynamically link against libacl), `libacl.so` and its dependency, `libattr.so`, are included so that they are available to end users (whose linkers need the `.so` files to perform dynamic linking).
* Since the `include/go-acl.h` interface is entirely system-agnostic, the Go code which uses it is as well, and should never need to be modified except for bug fixes and new features.

##Files

The important files are:

* `include/go-acl.h`: the platform-agnostic interface to the C implementation
* `src`: platform-specific implementations
* `res`: resources needed to build the C library such as libacl `.o` files and libacl and libattr `.so` files
* `lib`: where the resulting libraries go; cgo expects them to be in particular locations in `lib`

##Details

* When linking dynamically, there are a few things to watch out for. First, libgoacl is still linked statically - it's only libacl and libattr (which is a dependency of libacl) which are linked dynamically. Second, the linker needs an extra hint in order to find `libacl.so` and `libattr.so`; currently, this means that the cgo directive for dynamic linking includes explicit paths to these files in the `LDFLAGS` parameter (namely, `// #cgo LDFLAGS: -L ... ${SRCDIR}/lib/<os>/<arch>/dynamic/libacl.so ${SRCDIR}/lib/<os>/<arch>/dynamic/libattr.so ...`).
