package quota

import (
	"io/fs"
	"math"
	"os"
	"path/filepath"
)

func DirectoryUsage(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		sz := info.Size()
		if sz < 0 {
			return nil
		}
		if total > math.MaxInt64-sz {
			total = math.MaxInt64
			return nil
		}
		total += sz
		return nil
	})
	if os.IsNotExist(err) {
		return 0, nil
	}
	return total, err
}

func MaxFileSize(root, local string, quotaBytes int64) (int64, int64, error) {
	existing := int64(0)
	if st, err := os.Stat(local); err == nil {
		existing = st.Size()
	} else if !os.IsNotExist(err) {
		return 0, 0, err
	}
	if quotaBytes <= 0 {
		return math.MaxInt64, existing, nil
	}
	used, err := DirectoryUsage(root)
	if err != nil {
		return 0, 0, err
	}
	baseUsed := used - existing
	maxFile := quotaBytes - baseUsed
	if maxFile < 0 {
		maxFile = 0
	}
	return maxFile, existing, nil
}
