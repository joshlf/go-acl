#include "../include/go-grp-unix.h"
#include <grp.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

char *go_get_groupname(unsigned long gid) {
	struct group grp;
	struct group *res;
	// FreeBSD doesn't have _SC_GETPW_R_SIZE_MAX,
	// but as of this writing, we don't support
	// FreeBSD anyway, so it doesn't matter
	char *buf;
	int buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (buflen < 0) {
		return NULL;
	}
	buf = malloc(buflen);
	if (buf == NULL) {
		return NULL;
	}
	int code = getgrgid_r((int)gid, &grp, buf, buflen, &res);
	if (code < 0) {
		free(buf);
		return NULL;
	}
	int namelen = strlen(grp.gr_name);
	if (namelen < 0) {
		free(buf);
		return NULL;
	}
	char *name = malloc(sizeof(*name) * (namelen + 1));
	if (name == NULL) {
		return NULL;
	}
	name[namelen] = '\0';
	if (strncpy(name, grp.gr_name, namelen) < 0) {
		free(buf);
		free(name);
		return NULL;
	}
	free(buf);
	return name;
}