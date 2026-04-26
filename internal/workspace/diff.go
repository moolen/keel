package workspace

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

type Change struct {
	Path string
}

type Diff struct {
	Added    []Change
	Modified []Change
	Deleted  []Change
}

func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Modified) == 0 && len(d.Deleted) == 0
}

func DiffDirectories(hostDir, vmDir string) (Diff, error) {
	hostFiles, err := scanDir(hostDir)
	if err != nil {
		return Diff{}, err
	}
	vmFiles, err := scanDir(vmDir)
	if err != nil {
		return Diff{}, err
	}

	var diff Diff
	for path, vmHash := range vmFiles {
		hostHash, exists := hostFiles[path]
		switch {
		case !exists:
			diff.Added = append(diff.Added, Change{Path: path})
		case hostHash != vmHash:
			diff.Modified = append(diff.Modified, Change{Path: path})
		}
	}
	for path := range hostFiles {
		if _, exists := vmFiles[path]; !exists {
			diff.Deleted = append(diff.Deleted, Change{Path: path})
		}
	}

	sortChanges(diff.Added)
	sortChanges(diff.Modified)
	sortChanges(diff.Deleted)
	return diff, nil
}

func scanDir(root string) (map[string][32]byte, error) {
	files := map[string][32]byte{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		hash, err := hashFile(path)
		if err != nil {
			return err
		}
		files[rel] = hash
		return nil
	})
	return files, err
}

func hashFile(path string) ([32]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return [32]byte{}, fmt.Errorf("hash %s: %w", path, err)
	}

	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	return sum, nil
}

func sortChanges(changes []Change) {
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Path < changes[j].Path
	})
}
