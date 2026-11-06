//go:build !windows

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateRefusesSymlinkAndUsesOwnerOnlyMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := Create(link); err == nil {
		f.Close()
		t.Fatal("Create followed a symlink")
	}
	if f, err := Append(link); err == nil {
		f.Close()
		t.Fatal("Append followed a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("symlink target was modified")
	}

	p := filepath.Join(dir, "new")
	if err := WriteFile(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %v is readable by others", fi.Mode().Perm())
	}
}
