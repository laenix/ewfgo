package forensic

import (
	"context"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker"
	"github.com/laenix/ewfgo/internal/data/encryption/luks"
	"github.com/laenix/ewfgo/internal/data/filesystems/probe"
	"github.com/laenix/ewfgo/internal/data/partition/corestorage"
)

// EncryptionInfo summarizes the encryption layer of a volume. It carries
// metadata only: no key material, recovery password or master key is exposed.
type EncryptionInfo struct {
	// Format is "BitLocker", "LUKS1", "LUKS2" or "CoreStorage".
	Format string
	// Method is the recorded cipher/mode ("AES-XTS", "aes-xts-plain64", ...).
	Method string
	// UUID/Label are the volume identifiers the header records.
	UUID  string
	Label string

	// KeySlots/ActiveKeySlots describe LUKS key slots; Protectors describes
	// BitLocker key protectors (a recovery password is one kind).
	KeySlots       int
	ActiveKeySlots int
	Protectors     int
	// HasRecoveryPassword reports a BitLocker recovery-password protector.
	HasRecoveryPassword bool

	SectorSize   uint32
	VolumeBytes  uint64
	HeaderBytes  uint64
	MetadataOnly bool

	// Unsupported lists operations this reader refuses (for example "unlock"
	// and "decrypt") so a report can state them exactly.
	Unsupported []string
}

// Encryption parses the encryption metadata of an encrypted partition. It
// returns nil, nil when the partition does not carry a recognised encryption
// header. BitLocker volumes can be opened with UnlockBitLocker; the returned
// info names operations this metadata path still refuses in Unsupported.
func (p *Partition) Encryption(ctx context.Context) (*EncryptionInfo, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return readEncryption(p.src, p.format)
}

// Encryption parses encryption metadata for a whole-volume image without a
// partition table.
func (i *Image) Encryption(ctx context.Context) (*EncryptionInfo, error) {
	report, err := i.analysis(ctx)
	if err != nil {
		return nil, err
	}
	return readEncryption(i.source, report.VolumeFormat)
}

func readEncryption(src ByteSource, kind probe.Kind) (*EncryptionInfo, error) {
	switch kind {
	case probe.BitLocker:
		info, err := bitlocker.Read(src)
		if err != nil {
			return nil, fmt.Errorf("bitlocker header: %w", err)
		}
		if info == nil {
			return nil, nil
		}
		return &EncryptionInfo{
			Format:              "BitLocker",
			Method:              info.EncryptionMethod,
			KeySlots:            0,
			Protectors:          info.ProtectorCount(),
			HasRecoveryPassword: info.HasRecoveryPassword(),
			SectorSize:          info.SectorSize,
			VolumeBytes:         info.VolumeBytes,
			MetadataOnly:        true,
			Unsupported:         append([]string(nil), info.Unsupported...),
		}, nil

	case probe.LUKS:
		info, err := luks.Read(src)
		if err != nil {
			return nil, fmt.Errorf("LUKS header: %w", err)
		}
		if info == nil {
			return nil, nil
		}
		return &EncryptionInfo{
			Format:         fmt.Sprintf("LUKS%d", info.Version),
			Method:         info.EncryptionMethod(),
			UUID:           info.UUID,
			Label:          info.Label,
			KeySlots:       len(info.Keyslots),
			ActiveKeySlots: info.ActiveKeyslots,
			SectorSize:     info.SectorSize,
			VolumeBytes:    info.VolumeBytes,
			HeaderBytes:    info.HeaderBytes,
			MetadataOnly:   true,
			Unsupported:    append([]string(nil), info.Unsupported...),
		}, nil

	case probe.CoreStorage:
		volume, err := corestorage.Read(src)
		if err != nil {
			return nil, fmt.Errorf("CoreStorage header: %w", err)
		}
		if volume == nil {
			return nil, nil
		}
		return &EncryptionInfo{
			Format:       "CoreStorage",
			Method:       volume.EncryptionMethodLabel(),
			UUID:         volume.PhysicalVolumeUUID,
			SectorSize:   volume.BytesPerSector,
			VolumeBytes:  volume.PhysicalVolumeSize,
			MetadataOnly: true,
			Unsupported:  []string{"unlock", "decrypt", "logical-volume assembly"},
		}, nil

	default:
		return nil, nil
	}
}
