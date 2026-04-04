//go:build windows

package safefile

import (
	"fmt"
	"os"
)

func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to open symlink: %s", path)
	}
	return os.OpenFile(path, os.O_RDONLY, 0)
}
