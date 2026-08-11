package helperaudit

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivilegedProcessBoundaryAST(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve audit source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if err := Run(root); err != nil {
		t.Fatal(err)
	}
}
