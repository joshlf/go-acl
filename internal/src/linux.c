#include "../include/go-acl.h"

#include <sys/types.h>
#include <sys/acl.h>
#include <acl/libacl.h>
#include <string.h>
#include <stdlib.h>

go_acl_t go_acl_get_file_impl(char *path, acl_type_t type);
int go_acl_set_file_impl(char *path, go_acl_t go_acl, acl_type_t type);

go_acl_t go_acl_convert_from_native(acl_t acl);
acl_t go_acl_convert_to_native(go_acl_t go_acl, id_t **ids);
int go_acl_convert_entry_from_native(acl_entry_t entry, go_acl_entry_t *go_entry_p);
id_t *go_acl_convert_entry_to_native(go_acl_entry_t go_entry, acl_entry_t entry);

go_acl_entry_t go_acl_get_entry(go_acl_t go_acl, int index) {
	return go_acl->entries[index];
}

void go_acl_put_entry(go_acl_t go_acl, int index, go_acl_entry_t entry) {
	go_acl->entries[index] = entry;
}

go_acl_t go_acl_get_file(char *path) {
	return go_acl_get_file_impl(path, ACL_TYPE_ACCESS);
}

go_acl_t go_acl_get_file_default(char *path) {
	return go_acl_get_file_impl(path, ACL_TYPE_DEFAULT);
}

int go_acl_set_file(char *path, go_acl_t go_acl) {
	return go_acl_set_file_impl(path, go_acl, ACL_TYPE_ACCESS);
}

int go_acl_set_file_default(char *path, go_acl_t go_acl) {
	return go_acl_set_file_impl(path, go_acl, ACL_TYPE_DEFAULT);
}

go_acl_t go_acl_get_file_impl(char *path, acl_type_t type) {
	acl_t acl = acl_get_file(path, type);
	if (acl == NULL) {
		return NULL;
	}
	go_acl_t go_acl = go_acl_convert_from_native(acl);
	acl_free(acl);
	return go_acl;
}

int go_acl_set_file_impl(char *path, go_acl_t go_acl, acl_type_t type) {
	// Since acl_set_qualifier requires a pointer, but this
	// memory is not freed with acl_free, we have to keep
	// track of all the id_t pointers we allocate so that
	// we can free all of them after we've freed the acl.
	// A consequence of this is that we have to pass around
	// this buffer of ids so that helper functions can
	// populate it.
	id_t **ids = malloc(sizeof(*ids) * go_acl->num_entries);
	if (ids == NULL) {
		return -1;
	}
	acl_t acl = go_acl_convert_to_native(go_acl, ids);
	if (acl == NULL) {
		free(ids);
		return -1;
	}
	int code = acl_set_file(path, type, acl);
	acl_free(acl);
	for (int i = 0; i < go_acl->num_entries; i++) {
		free(ids[i]);
	}
	free(ids);
	return code;
}

go_acl_t go_acl_convert_from_native(acl_t acl) {
	go_acl_t go_acl = malloc(sizeof(*go_acl));
	if (go_acl == NULL) {
		return NULL;
	}
	go_acl->num_entries = 0;
	acl_entry_t entry;
	// first count how many entries there are
	while (1) {
		int code = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry);
		if (code == 0) {
			break;
		} else if (code < 0) {
			free(go_acl);
			return NULL;
		}
		go_acl->num_entries++;
	}

	go_acl->entries = malloc(sizeof(*(go_acl->entries)) * go_acl->num_entries);
	if (go_acl->entries == NULL) {
		free(go_acl);
		return NULL;
	}
	for (int i = 0; i < go_acl->num_entries; i++) {
		int code = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry);
		// assume that code is nonzero (which would imply that there
		// were a different amount of entries the second time around,
		// which would be a bug in libacl)
		if (code < 0) {
			free(go_acl->entries);
			free(go_acl);
			return NULL;
		}
		code = go_acl_convert_entry_from_native(entry, &(go_acl->entries[i]));
		if (code < 0) {
			free(go_acl->entries);
			free(go_acl);
			return NULL;
		}
	}
	return go_acl;
}

int go_acl_convert_entry_from_native(acl_entry_t entry, go_acl_entry_t *go_entry_p) {
	acl_tag_t tag;
	int code;
	if ((code = acl_get_tag_type(entry, &tag)) < 0) {
		return code;
	}
	switch (tag) {
	case ACL_USER_OBJ:
		go_entry_p->tag = TAG_USER_OBJ;
		break;
	case ACL_USER:
		go_entry_p->tag = TAG_USER;
		break;
	case ACL_GROUP_OBJ:
		go_entry_p->tag = TAG_GROUP_OBJ;
		break;
	case ACL_GROUP:
		go_entry_p->tag = TAG_GROUP;
		break;
	case ACL_MASK:
		go_entry_p->tag = TAG_MASK;
		break;
	case ACL_OTHER:
		go_entry_p->tag = TAG_OTHER;
		break;
	}

	acl_permset_t perms;
	code = acl_get_permset(entry, &perms);
	if (code < 0) {
		return code;
	}
	go_entry_p->perms = 0;
	code = acl_get_perm(perms, ACL_READ);
	if (code < 0) {
		return code;
	} else if (code > 0) {
		go_entry_p->perms |= 4;
	}
	code = acl_get_perm(perms, ACL_WRITE);
	if (code < 0) {
		return code;
	} else if (code > 0) {
		go_entry_p->perms |= 2;
	}
	code = acl_get_perm(perms, ACL_EXECUTE);
	if (code < 0) {
		return code;
	} else if (code > 0) {
		go_entry_p->perms |= 1;
	}

	go_entry_p->qualifier = 0;
	if (go_entry_p->tag == TAG_USER || go_entry_p->tag == TAG_GROUP) {
		void *id_ptr = acl_get_qualifier(entry);
		if (id_ptr == NULL) {
			return -1;
		}
		go_entry_p->qualifier = *(id_t *)id_ptr;
	}

	return 0;
}

// save all of the ids so they can be freed afterwards
acl_t go_acl_convert_to_native(go_acl_t go_acl, id_t **ids) {
	acl_t acl = acl_init(go_acl->num_entries);
	if (acl == NULL) {
		return NULL;
	}
	for (int i = 0; i < go_acl->num_entries; i++) {
		acl_entry_t entry;
		int code = acl_create_entry(&acl, &entry);
		if (code < 0) {
			for (int j = 0; j < i; j++) {
				free(ids[i]);
			}
			acl_free(acl);
			return NULL;
		}
		ids[i] = go_acl_convert_entry_to_native(go_acl->entries[i], entry);
		if (ids[i] == NULL) {
			for (int j = 0; j < i; j++) {
				free(ids[i]);
			}
			acl_free(acl);
			return NULL;
		}
	}
	return acl;
}

// returns the id_t used so that it can be freed later
id_t *go_acl_convert_entry_to_native(go_acl_entry_t go_entry, acl_entry_t entry) {
	int code;
	switch (go_entry.tag) {
	case TAG_USER_OBJ:
		code = acl_set_tag_type(entry, ACL_USER_OBJ);
		break;
	case TAG_USER:
		code = acl_set_tag_type(entry, ACL_USER);
		break;
	case TAG_GROUP_OBJ:
		code = acl_set_tag_type(entry, ACL_GROUP_OBJ);
		break;
	case TAG_GROUP:
		code = acl_set_tag_type(entry, ACL_GROUP);
		break;
	case TAG_MASK:
		code = acl_set_tag_type(entry, ACL_MASK);
		break;
	case TAG_OTHER:
		code = acl_set_tag_type(entry, ACL_OTHER);
		break;
	}
	if (code < 0) {
		return NULL;
	}

	acl_permset_t perms;
	if (acl_get_permset(entry, &perms) < 0) {
		return NULL;
	}
	if ((go_entry.perms & 4) != 0) {
		if (acl_add_perm(perms, ACL_READ) < 0) {
			return NULL;
		}
	}
	if ((go_entry.perms & 2) != 0) {
		if (acl_add_perm(perms, ACL_WRITE) < 0) {
			return NULL;
		}
	}
	if ((go_entry.perms & 1) != 0) {
		if (acl_add_perm(perms, ACL_EXECUTE) < 0) {
			return NULL;
		}
	}

	// Even though not all entries require a qualifier,
	// it's easier to just allocate one every time and
	// free all of them later. If we wanted to do it
	// differently, we'd have to figure out a way to
	// disambiguate between this function returning NULL
	// because of an error and it returning NULL because
	// we didn't need to allocate an id_t. It's much
	// easier to just eat the few extra allocations.
	id_t *id = malloc(sizeof(*id));
	if (id == NULL) {
		return NULL;
	}
	*id = go_entry.qualifier;
	if ((go_entry.tag == TAG_USER || go_entry.tag == TAG_GROUP) &&
			acl_set_qualifier(entry, id) < 0) {
		free(id);
		return NULL;
	}
	return id;
}

go_acl_t go_acl_create(int num_entries) {
	go_acl_t go_acl = malloc(sizeof(*go_acl));
	if (go_acl == NULL) {
		return NULL;
	}
	go_acl->num_entries = num_entries;
	go_acl->entries = malloc(sizeof(*(go_acl->entries)) * num_entries);
	if (go_acl->entries == NULL) {
		free(go_acl);
		return NULL;
	}
	return go_acl;
}

void go_acl_free(go_acl_t acl) {
	free(acl->entries);
	free(acl);
}

void go_free(void *ptr) {
	free(ptr);
}