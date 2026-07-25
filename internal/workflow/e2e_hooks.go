//go:build e2e

package workflow

import "io/fs"

// UnsafeSetRealIPReferenceIOForE2E wires deterministic reference-file IO into the
// e2e testserver without touching host /var/lib state.
func UnsafeSetRealIPReferenceIOForE2E(lstat func(string) (fs.FileInfo, error), read func(string) ([]byte, error)) func() {
	previousLstat := lstatRealIPReferenceFn
	previousRead := readRealIPReferenceFileFn
	lstatRealIPReferenceFn = lstat
	readRealIPReferenceFileFn = read
	return func() {
		lstatRealIPReferenceFn = previousLstat
		readRealIPReferenceFileFn = previousRead
	}
}
