package acl

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func mustMakeTempFile(t *testing.T) string {
	f, err := ioutil.TempFile("", "acl")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	return f.Name()
}

func mustNotError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestGet(t *testing.T) {
	f := mustMakeTempFile(t)
	defer os.Remove(f)
	_, err := Get(f)
	mustNotError(t, err)
}

func TestSet(t *testing.T) {
	f := mustMakeTempFile(t)
	defer os.Remove(f)
	acl, err := Get(f)
	mustNotError(t, err)
	for i := range acl {
		acl[i].Perms = (^acl[i].Perms) & 0x7 // Flip the rwx bits
	}
	err = Set(f, acl)
	mustNotError(t, err)
	acl2, err := Get(f)
	mustNotError(t, err)
	if !reflect.DeepEqual(acl, acl2) {
		t.Errorf("unexpected acl: want %v; got %v", acl, acl2)
	}
}
