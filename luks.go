package forensic

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/encryption/luks/unlock"
	"github.com/laenix/ewfgo/internal/data/source"
)

// LUKSUnlockInfo describes an unlocked LUKS volume. It carries no key
// material.
type LUKSUnlockInfo struct {
	Format        string
	Version       int
	Keyslot       int
	KDF           string
	Cipher        string
	Mode          string
	KeyBytes      int
	Stripes       uint64
	Iterations    uint64
	AreaOffset    uint64
	PayloadOffset uint64
	PayloadLen    uint64
	IVTweak       uint64
}

// LUKSVolume is a decrypted LUKS1/LUKS2 volume. Source is the plaintext byte
// stream; it is not closed independently of the image it came from.
type LUKSVolume struct {
	info   LUKSUnlockInfo
	source ByteSource
}

// Info returns the unlock summary.
func (v *LUKSVolume) Info() LUKSUnlockInfo { return v.info }

// Source returns the decrypted plaintext volume.
func (v *LUKSVolume) Source() ByteSource { return v.source }

// UnlockLUKS opens a LUKS1/LUKS2 partition with a passphrase. A wrong
// passphrase returns an error wrapping ErrDecrypt; the key is accepted only
// after the volume digest verifies it.
func (p *Partition) UnlockLUKS(ctx context.Context, passphrase string) (*LUKSVolume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return unlockLUKS(ctx, p.src, passphrase)
}

// UnlockLUKS opens a whole-volume LUKS1/LUKS2 image with a passphrase.
func (i *Image) UnlockLUKS(ctx context.Context, passphrase string) (*LUKSVolume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return unlockLUKS(ctx, i.source, passphrase)
}

// OpenLUKSSource unlocks a LUKS1/LUKS2 volume over an existing byte source.
// The source is not closed by the returned volume.
func OpenLUKSSource(ctx context.Context, src ByteSource, passphrase string) (*LUKSVolume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil LUKS source", ErrInvalidArgument)
	}
	return unlockLUKS(ctx, src, passphrase)
}

var luksSourceID atomic.Uint64

func unlockLUKS(ctx context.Context, src ByteSource, passphrase string) (*LUKSVolume, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	unlocked, err := unlock.Unlock(src, []byte(passphrase))
	if err != nil {
		switch {
		case errors.Is(err, unlock.ErrWrongPassphrase):
			return nil, fmt.Errorf("%w: luks: %v", ErrDecrypt, err)
		case errors.Is(err, unlock.ErrNotLUKS):
			return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
		case errors.Is(err, unlock.ErrUnsupportedCipher),
			errors.Is(err, unlock.ErrUnsupportedHash),
			errors.Is(err, unlock.ErrUnsupportedKDF),
			errors.Is(err, unlock.ErrUnsupportedFormat),
			errors.Is(err, unlock.ErrUnsupportedDigest),
			errors.Is(err, unlock.ErrUnsupportedSectorSize):
			return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
		default:
			return nil, fmt.Errorf("unlock luks: %w", err)
		}
	}
	id := source.ID(luksSourceID.Add(1) + 6_000_000)
	plain, err := unlocked.Open(id, src)
	if err != nil {
		return nil, fmt.Errorf("open decrypted LUKS volume: %w", err)
	}
	return &LUKSVolume{
		info: LUKSUnlockInfo{
			Format:        unlocked.Label(),
			Version:       unlocked.Version,
			Keyslot:       unlocked.Keyslot,
			KDF:           unlocked.KDF,
			Cipher:        unlocked.Cipher,
			Mode:          unlocked.CipherMode(),
			KeyBytes:      unlocked.KeyBytes,
			Stripes:       unlocked.Stripes,
			Iterations:    unlocked.Iterations,
			AreaOffset:    unlocked.AreaOffset,
			PayloadOffset: unlocked.PayloadOffset,
			PayloadLen:    unlocked.PayloadLen,
			IVTweak:       unlocked.IVTweak,
		},
		source: plain,
	}, nil
}
