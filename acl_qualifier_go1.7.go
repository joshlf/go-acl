// +build go1.7

package acl

import "os/user"

func init() {
	formatQualifier = func(q string, tag Tag) string {
		switch tag {
		case TagUser:
			usr, err := user.LookupId(q)
			if err != nil {
				return q
			}
			return usr.Username
		case TagGroup:
			grp, err := user.LookupGroupId(q)
			if err != nil {
				return q
			}
			return grp.Name
		default:
			return q
		}
	}
}
