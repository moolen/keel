package image

import "path/filepath"

func CachePath(cacheDir, ref string) string {
	return filepath.Join(cacheDir, ref)
}
