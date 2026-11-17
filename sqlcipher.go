package forensic

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/laenix/ewfgo/internal/data/containers/sqlcipher"
	"github.com/laenix/ewfgo/internal/data/source"
)

// ErrWrongPassphrase reports a SQLCipher key that did not verify the page-1
// HMAC. It also matches ErrDecrypt.
var ErrWrongPassphrase = sqlcipher.ErrWrongPassphrase

// SQLCipherDatabase is an unlocked SQLCipher-encrypted SQLite database. Its
// Source reads decrypted pages; every page is re-authenticated with its HMAC
// before decryption.
type SQLCipherDatabase struct {
	path   string
	src    *sqlcipher.Source
	closer io.Closer
}

// SQLCipherInfo describes the unlocked database.
type SQLCipherInfo struct {
	Version           string
	PageSize          uint32
	PageCount         uint64
	FileSize          uint64
	Cipher            string
	KDF               string
	HMAC              string
	KDFIterations     uint32
	HMACKDFIterations uint32
	ReserveBytes      int
	// Salt is the per-file salt, which is not secret.
	Salt string
}

// OpenSQLCipher unlocks a SQLCipher database with a passphrase, trying the
// SQLCipher 4, 3, 2 and 1 profiles in order. A wrong passphrase returns
// ErrWrongPassphrase; a plaintext SQLite database is not a SQLCipher file and
// is refused explicitly.
func OpenSQLCipher(ctx context.Context, imagePath, passphrase string, opts Options) (*SQLCipherDatabase, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if passphrase == "" {
		return nil, fmt.Errorf("%w: a SQLCipher passphrase is required", ErrInvalidArgument)
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open SQLCipher database %s: %w", imagePath, err)
	}
	unlocked, err := sqlcipher.UnlockAuto(1, raw, []byte(passphrase))
	if err != nil {
		raw.Close()
		if errors.Is(err, sqlcipher.ErrNoProfile) {
			return nil, fmt.Errorf("%w: %w: no SQLCipher profile verified page 1 for %s", ErrWrongPassphrase, ErrDecrypt, imagePath)
		}
		if errors.Is(err, sqlcipher.ErrNotSQLCipher) {
			return nil, fmt.Errorf("%w: %s is not a SQLCipher database: %v", ErrUnsupported, imagePath, err)
		}
		return nil, fmt.Errorf("unlock SQLCipher database %s: %w", imagePath, err)
	}
	return &SQLCipherDatabase{path: imagePath, src: unlocked, closer: raw}, nil
}

// OpenSQLCipherSource unlocks a SQLCipher database over an existing byte
// source. The source is not closed by SQLCipherDatabase.Close.
func OpenSQLCipherSource(ctx context.Context, src ByteSource, passphrase string, opts Options) (*SQLCipherDatabase, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil SQLCipher source", ErrInvalidArgument)
	}
	if passphrase == "" {
		return nil, fmt.Errorf("%w: a SQLCipher passphrase is required", ErrInvalidArgument)
	}
	unlocked, err := sqlcipher.UnlockAuto(1, src, []byte(passphrase))
	if err != nil {
		if errors.Is(err, sqlcipher.ErrNoProfile) {
			return nil, fmt.Errorf("%w: %w: no SQLCipher profile verified page 1", ErrWrongPassphrase, ErrDecrypt)
		}
		if errors.Is(err, sqlcipher.ErrNotSQLCipher) {
			return nil, fmt.Errorf("%w: source is not a SQLCipher database: %v", ErrUnsupported, err)
		}
		return nil, fmt.Errorf("unlock SQLCipher database: %w", err)
	}
	return &SQLCipherDatabase{src: unlocked}, nil
}

// Path returns the database path.
func (d *SQLCipherDatabase) Path() string { return d.path }

// Info returns the profile and page geometry used to unlock the database.
func (d *SQLCipherDatabase) Info() SQLCipherInfo {
	params := d.src.Params()
	salt := d.src.Salt()
	return SQLCipherInfo{
		Version:           params.Version.Label(),
		PageSize:          d.src.PageSize(),
		PageCount:         d.src.PageCount(),
		FileSize:          d.src.Len(),
		Cipher:            params.Cipher.Name(),
		KDF:               params.KDF.Name(),
		HMAC:              params.HMAC.Name(),
		KDFIterations:     params.KDFIterations,
		HMACKDFIterations: params.HMACKDFIterations,
		ReserveBytes:      params.ReserveBytes(),
		Salt:              hex.EncodeToString(salt[:]),
	}
}

// Source returns the decrypted database as a byte source. The SQLite header is
// visible at offset 0 and page reads are authenticated and decrypted.
func (d *SQLCipherDatabase) Source() ByteSource { return d.src }

// Close releases the database file.
func (d *SQLCipherDatabase) Close() error {
	if d.closer == nil {
		return nil
	}
	err := d.closer.Close()
	d.closer = nil
	return err
}
