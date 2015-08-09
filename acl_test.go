package acl

import (
	"fmt"
	"io/ioutil"
	"os"
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
	acl, err := Get(f)
	mustNotError(t, err)
	fmt.Println(acl)
}
