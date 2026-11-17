package forensic

import (
	"encoding/hex"
	"time"

	"github.com/laenix/ewfgo/internal/data/filesystems/befs"
	"github.com/laenix/ewfgo/internal/data/filesystems/gfs2"
	"github.com/laenix/ewfgo/internal/data/filesystems/hammer2"
	"github.com/laenix/ewfgo/internal/data/filesystems/hfs"
	"github.com/laenix/ewfgo/internal/data/filesystems/hpfs"
	"github.com/laenix/ewfgo/internal/data/filesystems/jffs2"
	"github.com/laenix/ewfgo/internal/data/filesystems/nilfs2"
	"github.com/laenix/ewfgo/internal/data/filesystems/ocfs2"
	"github.com/laenix/ewfgo/internal/data/filesystems/qnx6"
	"github.com/laenix/ewfgo/internal/data/filesystems/ubifs"
	"github.com/laenix/ewfgo/internal/data/filesystems/yaffs"
	"github.com/laenix/ewfgo/internal/data/filesystems/zfs"
	"github.com/laenix/ewfgo/internal/data/source"
)

func openHPFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := hpfs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	label := info.VolumeLabel
	if label == "" {
		label = info.VolumeName
	}
	fs := &dataFS{
		typ:    "HPFS",
		limits: limits,
		info: FSInfo{
			Type: "HPFS", Label: label, BlockSize: info.SectorBytes,
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e hpfs.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: e.Mode, UID: e.UID, GID: e.GID,
			Inode: uint64(e.Inode),
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	fs.free = func() (*FreeSpaceMap, error) {
		space, err := v.FreeSpace()
		if err != nil {
			return nil, err
		}
		runs := make([]FreeRun, 0, len(space.Runs()))
		for _, r := range space.Runs() {
			runs = append(runs, FreeRun{Offset: r.Offset, Length: r.Len})
		}
		return &FreeSpaceMap{
			FreeBytes: space.FreeBytes(), Covered: space.Covered(),
			Basis: space.Basis(), Runs: runs, Notes: space.Notes(),
		}, nil
	}
	return fs, nil
}

func openGFS2(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := gfs2.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "GFS2",
		limits: limits,
		info: FSInfo{
			Type: "GFS2", UUID: info.UUID, BlockSize: info.BlockSize,
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e gfs2.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: e.Mode,
			UID: e.UID, GID: e.GID, Inode: e.Inode,
			Modified: unixPtr(e.ModifyTime), Accessed: unixPtr(e.AccessTime),
			SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func unixPtr(value *int64) time.Time {
	if value == nil || *value == 0 {
		return time.Time{}
	}
	return time.Unix(*value, 0).UTC()
}

func openNILFS2(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := nilfs2.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "NILFS2",
		limits: limits,
		info: FSInfo{
			Type: "NILFS2", Label: info.VolumeName, UUID: info.UUID,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e nilfs2.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: uint32(e.Mode),
			UID: e.UID, GID: e.GID, Inode: e.Inode,
			SymlinkTarget: e.SymlinkTarget,
		}
		if e.HasMtime {
			entry.Modified = e.Mtime
		}
		if e.HasAtime {
			entry.Accessed = e.Atime
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openOCFS2(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := ocfs2.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "OCFS2",
		limits: limits,
		info: FSInfo{
			Type: "OCFS2", Label: info.VolumeLabel, UUID: info.UUID,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e ocfs2.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: uint32(e.Mode),
			UID: e.UID, GID: e.GID, Inode: e.Inode,
			SymlinkTarget: e.SymlinkTarget,
		}
		if e.HasMtime {
			entry.Modified = e.Mtime
		}
		if e.HasAtime {
			entry.Accessed = e.Atime
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openUBIFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := ubifs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "UBIFS",
		limits: limits,
		info: FSInfo{
			Type: "UBIFS", UUID: hex.EncodeToString(info.UUID[:]),
			BlockSize: info.LEBSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e ubifs.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: e.Mode,
			UID: e.UID, GID: e.GID, Inode: e.Inode,
			SymlinkTarget: e.SymlinkTarget,
		}
		if e.HasMtime {
			entry.Modified = e.Mtime
		}
		if e.HasAtime {
			entry.Accessed = e.Atime
		}
		if e.HasCtime {
			entry.Created = e.Ctime
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openHFSClassic(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := hfs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "HFS",
		limits: limits,
		info: FSInfo{
			Type: "HFS", Label: info.Name, BlockSize: info.AllocationBlockSize,
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e hfs.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: e.Mode,
			UID: e.UID, GID: e.GID, Inode: uint64(e.Inode),
		}
		if e.HasModified {
			entry.Modified = e.Modified
		}
		if e.HasCreated {
			entry.Created = e.Created
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openBeFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := befs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "BeFS",
		limits: limits,
		info: FSInfo{
			Type: "BeFS", Label: info.Name, BlockSize: info.BlockSize,
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e befs.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: e.Mode,
			UID: uint32(e.UID), GID: uint32(e.GID), Inode: e.Inode,
			SymlinkTarget: e.SymlinkTarget,
		}
		if e.HasModified {
			entry.Modified = e.Modified
		}
		if e.HasCreated {
			entry.Created = e.Created
		}
		if e.HasChanged {
			entry.Accessed = e.Changed
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openYAFFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := yaffs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "YAFFS2",
		limits: limits,
		info: FSInfo{
			Type: "YAFFS2", BlockSize: uint32(info.PageSize),
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e yaffs.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: e.Mode,
			UID: e.UID, GID: e.GID, Inode: e.Inode,
		}
		if e.HasMtime {
			entry.Modified = e.Mtime
		}
		if e.HasAtime {
			entry.Accessed = e.Atime
		}
		if e.IsSymlink {
			if target, err := v.SymlinkTarget(e.Path); err == nil {
				entry.SymlinkTarget = target
			}
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openJFFS2(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := jffs2.Open(src)
	if err != nil {
		return nil, err
	}
	fs := &dataFS{
		typ:    "JFFS2",
		limits: limits,
		info: FSInfo{
			Type: "JFFS2", SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e jffs2.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: e.Mode,
			UID: e.UID, GID: e.GID, Inode: uint64(e.Inode),
			Modified: e.Mtime, Accessed: e.Atime, Created: e.Ctime,
			SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func hammer2Time(micros *int64) time.Time {
	if micros == nil {
		return time.Time{}
	}
	return time.UnixMicro(*micros).UTC()
}

func openHAMMER2(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := hammer2.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "HAMMER2",
		limits: limits,
		info: FSInfo{
			Type: "HAMMER2", UUID: info.FSID, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e hammer2.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: e.Mode,
			UID: e.UID, GID: e.GID, Inode: e.Inode,
			Modified: hammer2Time(e.Modified), Accessed: hammer2Time(e.Accessed),
			Created: hammer2Time(e.Created), SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openZFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := zfs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	blockSize := uint32(0)
	if info.AshiftPresent && info.Ashift < 32 {
		blockSize = uint32(1) << info.Ashift
	}
	fs := &dataFS{
		typ:    "ZFS",
		limits: limits,
		info: FSInfo{
			Type: "ZFS", Label: info.PoolName, BlockSize: blockSize,
			SectorSize: sector, ReadOnly: true,
		},
	}
	mount := v.Root()
	convert := func(e zfs.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: e.Mode,
			UID: uint32(e.UID), GID: uint32(e.GID), Inode: e.Inode,
			SymlinkTarget: e.SymlinkTarget,
		}
		if e.HasMtime {
			entry.Modified = e.Mtime
		}
		if e.HasAtime {
			entry.Accessed = e.Atime
		}
		if e.HasBtime {
			entry.Created = e.Btime
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := mount.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := mount.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := mount.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openQNX6(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := qnx6.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "QNX6",
		limits: limits,
		info: FSInfo{
			Type: "QNX6", Label: info.VolumeID, BlockSize: info.BlockSize,
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e qnx6.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: uint32(e.Mode), UID: e.UID,
			GID: e.GID, Inode: e.Inode,
			Modified: unixPtr(e.Modified), Accessed: unixPtr(e.Accessed),
			Created: unixPtr(e.Created), SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}
