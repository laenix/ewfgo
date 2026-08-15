package ewf

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

// ReadSector reads a single sector at the given logical block address (LBA).
func (e *EWFImage) ReadSector(lba uint64) ([]byte, error) {
	return e.ReadSectors(lba, 1)
}

// ReadSectors reads multiple sectors starting at the given logical block
// address (LBA). It uses the table mapping to find compressed sector data and
// decompresses as needed. On any resolution or decompression failure it
// returns an error — it never falls back to returning raw EWF container bytes.
func (e *EWFImage) ReadSectors(lba uint64, count uint64) ([]byte, error) {
	if e.ewf == nil || e.ewf.Filepath() == "" {
		return nil, fmt.Errorf("no file opened")
	}
	return e.ewf.ReadSectorData(lba, count)
}

// StoredHashes returns the acquisition hashes stored in the E01 image. The MD5
// hash comes from the image's "hash" or "digest" section; the SHA1 hash only
// from a "digest" section. A nil slice means the image carries no such hash.
func (e *EWFImage) StoredHashes() (md5Hash, sha1Hash []byte) {
	if e == nil || e.ewf == nil {
		return nil, nil
	}
	return e.ewf.StoredMD5, e.ewf.StoredSHA1
}

// HashVerifyResult reports the result of VerifyImageHash: the hashes stored in
// the E01 versus the hashes computed over the image's media data.
type HashVerifyResult struct {
	StoredMD5    []byte // 16 bytes from the "hash"/"digest" section, nil if absent
	StoredSHA1   []byte // 20 bytes from the "digest" section, nil if absent
	ComputedMD5  []byte // MD5 of the whole media data
	ComputedSHA1 []byte // SHA1 of the whole media data
	MD5Match     bool   // true iff both StoredMD5 and ComputedMD5 are present and equal
	SHA1Match    bool   // true iff both StoredSHA1 and ComputedSHA1 are present and equal
	BytesHashed  uint64 // total media bytes streamed
}

// VerifyImageHash streams the entire media data (TotalSectors × SectorSize
// bytes) through the exact-decompression read path and compares the computed
// MD5/SHA1 against the acquisition hashes stored in the E01. This is the
// end-to-end integrity check: if it matches, every byte a reader sees is byte
// for byte the data the forensic tool acquired.
func (e *EWFImage) VerifyImageHash() (*HashVerifyResult, error) {
	if e == nil || e.ewf == nil || e.ewf.Filepath() == "" {
		return nil, fmt.Errorf("no file opened")
	}
	sectorBytes := e.SectorSize()
	if sectorBytes == 0 {
		sectorBytes = 512
	}
	totalSectors := e.TotalSectors()

	md5h := md5.New()
	sha1h := sha1.New()
	// 4096 sectors ≈ 2 MiB per read at 512-byte sectors.
	const chunkSectors = 4096
	var hashed uint64
	for lba := uint64(0); lba < totalSectors; {
		n := totalSectors - lba
		if n > chunkSectors {
			n = chunkSectors
		}
		buf, err := e.ewf.ReadSectorData(lba, n)
		if err != nil {
			return nil, fmt.Errorf("verify: read at sector %d: %w", lba, err)
		}
		md5h.Write(buf)
		sha1h.Write(buf)
		hashed += uint64(len(buf))
		lba += n
	}

	res := &HashVerifyResult{
		StoredMD5:    e.ewf.StoredMD5,
		StoredSHA1:   e.ewf.StoredSHA1,
		ComputedMD5:  md5h.Sum(nil),
		ComputedSHA1: sha1h.Sum(nil),
		BytesHashed:  hashed,
	}
	res.MD5Match = len(res.StoredMD5) == md5.Size && bytes.Equal(res.StoredMD5, res.ComputedMD5)
	res.SHA1Match = len(res.StoredSHA1) == sha1.Size && bytes.Equal(res.StoredSHA1, res.ComputedSHA1)
	return res, nil
}
