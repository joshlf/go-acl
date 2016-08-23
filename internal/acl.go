package internal

import "os"

type ACL []Entry

// Tag is the type of an ACL entry tag.
type Tag tag

const (
	TagUserObj  Tag = tagUserObj
	TagUser         = tagUser
	TagGroupObj     = tagGroupObj
	TagGroup        = tagGroup
	TagMask         = tagMask
	TagOther        = tagOther
)

type Entry struct {
	Tag       Tag
	Qualifier string
	Perms     os.FileMode
}

func Get(path string) (ACL, error) {
	return get(path)
}

func GetDefault(path string) (ACL, error) {
	return get(path)
}

func Set(path string, acl ACL) error {
	return set(path, acl)
}

func SetDefault(path string, acl ACL) error {
	return set(path, acl)
}

// FormatQualifier attempts to format the qualifier,
// q, in a human-readable format (for example, by
// looking up the username for a userid). If a
// human-readable format cannot be found, q is returned.
func FormatQualifier(q string, tag Tag) string {
	return formatQualifier(q, tag)
}

// overwrite in other files to implement platform-specific behavior
var formatQualifier = func(q string, tag Tag) string { return q }
