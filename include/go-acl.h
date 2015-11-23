#ifndef ACL_IMPL_H
#define ACL_IMPL_H

typedef enum go_acl_tag_t {
	TAG_UNDEFINED, // Start with TAG_UNDEFINED so that the Go zero value matches
	TAG_USER_OBJ,
	TAG_USER,
	TAG_GROUP_OBJ,
	TAG_GROUP,
	TAG_MASK,
	TAG_OTHER
} go_acl_tag_t;

typedef struct go_acl_entry_t {
	go_acl_tag_t tag;
	unsigned long qualifier;
	int perms;
} go_acl_entry_t;

typedef struct go_acl_t {
	int num_entries;
	go_acl_entry_t *entries;
} *go_acl_t;


// go_acl_get_file gets the acl associated with path.
// If it returns an error, the returned acl will not 
// be initialized, and should not be freed.
go_acl_t go_acl_get_file(char *path);

// go_acl_get_file_default is like go_acl_get_file,
// except that it gets the default acl.
go_acl_t go_acl_get_file_default(char *path);

// go_acl_set_file sets the acl associated with path.
int go_acl_set_file(char *path, go_acl_t go_acl);

// go_acl_set_file_default is like go_acl_set_file,
// except that it sets the default acl.
int go_acl_set_file_default(char *path, go_acl_t go_acl);

// go_acl_get_entry retrieves the entry at the
// given index. It is intended to be used by
// Go (since Go can't perform indexing operations
// on C pointers).
go_acl_entry_t go_acl_get_entry(go_acl_t go_acl, int index);

// go_acl_put_entry overwrites the entry at the
// given index with the given entry. The given
// acl must already have sufficient space allocated
// (for example, by calling go_acl_create). This
// function is intended to be used by Go (since Go
// can't perform indexing operations on C pointers).
void go_acl_put_entry(go_acl_t go_acl, int index, go_acl_entry_t entry);

// go_acl_create creates an uninitialized acl that
// can be filled in by the caller.
go_acl_t go_acl_create(int num_entries);

// go_acl_free frees an allocated go_acl_t.
void go_acl_free(go_acl_t acl);

// go_free is a stub to stdlib.h free. It is here
// so that a Go caller can avoid importing any header
// file other than this one. go_free should be used
// for freeing objects (primarily C strings) that do
// not have a custom free method.
void go_free(void *ptr);

#endif