package forensic

import (
	"github.com/laenix/ewfgo/internal/data/containers/androidbackup"
	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

// openAndroidBackup exposes the tar payload inside an Android or MIUI backup
// through the archive.Reader interface. Encrypted backups are refused by the
// container reader with an explicit error.
func openAndroidBackup(src source.ByteSource, limits archive.Limits) (archive.Reader, error) {
	backup, err := androidbackup.Open(1, src, limits)
	if err != nil {
		return nil, err
	}
	return backup.Reader, nil
}
