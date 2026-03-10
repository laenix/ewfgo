package filesystem

import (
	"fmt"
)

// BitLocker/LUKS encrypted volume detection
// Note: Full decryption is not possible without keys, but we can identify the volume type

type BitLocker struct {
	encrypted        bool
	version          string
	volumeGUID       [16]byte
	protectionStatus int
	metadataSize     uint64

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// BitLocker Volume Header (at offset 0)
type BitLockerVolumeHeader struct {
	Signature       [8]byte    // "-FVE-FS-"
	MajorVersion    uint16     // 1 or 2
	MinorVersion    uint16     // Usually 1
	HeaderSize      uint32     // Size of header
	CopyOfHeader    uint32     // Offset to backup header
	VolumeGUID      [16]byte  // GUID of volume
	NonPersistData  [72]byte  // Non-persisted data
}

// LUKS Header (at offset 0)
type LUKSHeader struct {
	Magic           [6]byte    // "LUKS\xba\xbe"
	Version         uint16     // LUKS version (usually 1)
	CipherName      [32]byte   // Cipher name (e.g., "aes")
	CipherMode      [32]byte   // Cipher mode (e.g., "xts-plain64")
	HashSpec        [32]byte   // Hash specification
	PayloadOffset   uint32     // Offset of encrypted data
	MasterKeyBytes  uint32     // Size of master key
	_               [20]byte   // Padding
	UUID           [40]byte   // UUID
	_               [1283896]byte // Key material (mostly zeros)
}

const BitLockerMagic = "-FVE-FS-"
const LUKSMagic = "LUKS\xba\xbe"

func (bl *BitLocker) Type() FileSystemType {
	return FS_BITLOCKER
}

func (bl *BitLocker) Open(sectorData []byte) error {
	if len(sectorData) < 512 {
		return fmt.Errorf("BitLocker: sector data too small")
	}

	// Check for BitLocker signature
	if len(sectorData) >= 8 && string(sectorData[:8]) == BitLockerMagic {
		bl.version = "BitLocker"
		bl.encrypted = true
		bl.metadataSize = 0x100000 // 1MB typical
		return nil
	}

	// Check for LUKS signature
	if len(sectorData) >= 6 && string(sectorData[:6]) == "LUKS" {
		bl.version = "LUKS"
		bl.encrypted = true

		if len(sectorData) >= 4096 {
			// Try to parse some fields
			bl.version = "LUKS (dm-crypt)"
		}
		return nil
	}

	return fmt.Errorf("BitLocker: not an encrypted volume")
}

func (bl *BitLocker) Close() error { return nil }

func (bl *BitLocker) GetVolumeLabel() string {
	if bl.version == "BitLocker" {
		return "BitLocker Encrypted Volume"
	}
	return "LUKS Encrypted Volume"
}

func (bl *BitLocker) IsEncrypted() bool {
	return bl.encrypted
}

func (bl *BitLocker) GetEncryptionType() string {
	return bl.version
}

func (bl *BitLocker) ListDirectory(path string) ([]DirectoryEntry, error) {
	if bl.encrypted {
		return nil, fmt.Errorf("BitLocker: volume is encrypted, cannot list without key")
	}
	return nil, nil
}

func (bl *BitLocker) GetFile(path string) ([]byte, error) {
	if bl.encrypted {
		return nil, fmt.Errorf("BitLocker: volume is encrypted, cannot read without key")
	}
	return nil, nil
}

func (bl *BitLocker) GetFileByPath(path string) (*FileInfo, error) {
	return nil, fmt.Errorf("encrypted volume")
}

func (bl *BitLocker) SearchFiles(rootPath string, predicate func(FileInfo) bool) ([]FileInfo, error) {
	return nil, fmt.Errorf("encrypted volume")
}

func init() {
	RegisterFileSystem(FS_BITLOCKER, func() FileSystem {
		return &BitLocker{}
	})
	RegisterFileSystem(FS_LUKS, func() FileSystem {
		return &BitLocker{}
	})
}