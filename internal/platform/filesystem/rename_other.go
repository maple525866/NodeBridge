//go:build !linux && !darwin && !windows

package filesystem

import "os"

func renameNoReplace(src, dst string) error {
	if err := os.Link(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}
