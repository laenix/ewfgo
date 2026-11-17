package forensic

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker"
	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker/unlock"
	"github.com/laenix/ewfgo/internal/data/source"
)

// BitLockerCredentials names the key material used to unlock a BitLocker
// volume. Exactly one field must be set. The recovery password is the
// 48-digit number; Password is a user password; StartupKey is a 256-bit
// external key.
type BitLockerCredentials struct {
	RecoveryPassword string
	Password         string
	StartupKey       []byte
}

// BitLockerUnlockInfo describes an unlocked BitLocker volume. It carries no
// key material.
type BitLockerUnlockInfo struct {
	Method        string
	CipherMode    string
	Protector     string
	Protectors    int
	CipherKeyBits uint32
	FVEKBytes     int
	DataOffset    uint64
	VolumeBytes   uint64
}

// BitLockerVolume is a decrypted BitLocker volume. Source is the plaintext
// byte stream; it is not closed independently of the image it came from.
type BitLockerVolume struct {
	info   BitLockerUnlockInfo
	source ByteSource
}

// Info returns the unlock summary.
func (v *BitLockerVolume) Info() BitLockerUnlockInfo { return v.info }

// Source returns the decrypted plaintext volume.
func (v *BitLockerVolume) Source() ByteSource { return v.source }

// UnlockBitLocker opens a BitLocker partition with the supplied credentials.
// A wrong key returns an error wrapping ErrDecrypt; unsupported methods and
// unfinished conversions are refused explicitly.
func (p *Partition) UnlockBitLocker(ctx context.Context, creds BitLockerCredentials) (*BitLockerVolume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	metadata, err := bitlocker.Read(p.src)
	if err != nil {
		return nil, fmt.Errorf("bitlocker header: %w", err)
	}
	if metadata == nil {
		return nil, fmt.Errorf("%w: partition is not BitLocker-encrypted", ErrUnsupported)
	}
	return unlockBitLocker(ctx, p.src, metadata, creds)
}

// UnlockBitLocker opens a whole-volume BitLocker image with the supplied
// credentials.
func (i *Image) UnlockBitLocker(ctx context.Context, creds BitLockerCredentials) (*BitLockerVolume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	metadata, err := bitlocker.Read(i.source)
	if err != nil {
		return nil, fmt.Errorf("bitlocker header: %w", err)
	}
	if metadata == nil {
		return nil, fmt.Errorf("%w: image is not BitLocker-encrypted", ErrUnsupported)
	}
	return unlockBitLocker(ctx, i.source, metadata, creds)
}

// OpenBitLockerSource unlocks a BitLocker volume over an existing byte source.
// The source is not closed by the returned volume.
func OpenBitLockerSource(ctx context.Context, src ByteSource, creds BitLockerCredentials) (*BitLockerVolume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil BitLocker source", ErrInvalidArgument)
	}
	metadata, err := bitlocker.Read(src)
	if err != nil {
		return nil, fmt.Errorf("bitlocker header: %w", err)
	}
	if metadata == nil {
		return nil, fmt.Errorf("%w: source is not BitLocker-encrypted", ErrUnsupported)
	}
	return unlockBitLocker(ctx, src, metadata, creds)
}

var bitlockerSourceID atomic.Uint64

func unlockBitLocker(ctx context.Context, src ByteSource, metadata *bitlocker.Info, creds BitLockerCredentials) (*BitLockerVolume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	set := 0
	if creds.RecoveryPassword != "" {
		set++
	}
	if creds.Password != "" {
		set++
	}
	if len(creds.StartupKey) != 0 {
		set++
	}
	if set != 1 {
		return nil, fmt.Errorf("%w: set exactly one of RecoveryPassword, Password or StartupKey", ErrInvalidArgument)
	}

	var (
		unlocked *unlock.Unlocked
		err      error
	)
	switch {
	case creds.RecoveryPassword != "":
		unlocked, err = unlock.Unlock(src, metadata, []byte(creds.RecoveryPassword))
	case creds.Password != "":
		unlocked, err = unlock.UnlockWithPassword(src, metadata, []byte(creds.Password))
	default:
		unlocked, err = unlock.UnlockWithStartupKey(src, metadata, creds.StartupKey)
	}
	if err != nil {
		if errors.Is(err, unlock.ErrWrongPassphrase) {
			return nil, fmt.Errorf("%w: bitlocker: %v", ErrDecrypt, err)
		}
		if errors.Is(err, unlock.ErrUnsupportedMethod) || errors.Is(err, unlock.ErrUnfinishedConversion) {
			return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
		}
		return nil, fmt.Errorf("unlock bitlocker: %w", err)
	}

	id := source.ID(bitlockerSourceID.Add(1) + 5_000_000)
	plain, err := unlocked.Open(id, src)
	if err != nil {
		return nil, fmt.Errorf("open decrypted BitLocker volume: %w", err)
	}
	return &BitLockerVolume{
		info: BitLockerUnlockInfo{
			Method:        unlocked.MethodLabel(),
			CipherMode:    unlocked.CipherMode(),
			Protector:     unlocked.ProtectorKind().String(),
			Protectors:    unlocked.Protectors(),
			CipherKeyBits: unlocked.CipherKeyBits(),
			FVEKBytes:     unlocked.KeyBytes(),
			DataOffset:    unlocked.DataOffset(),
			VolumeBytes:   plain.Len(),
		},
		source: plain,
	}, nil
}
