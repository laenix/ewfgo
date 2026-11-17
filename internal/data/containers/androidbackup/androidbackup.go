// Package androidbackup reads Android full backups (`.ab`) and MIUI `.bak`
// wrappers: the text header, an optional zlib stream, and the tar archive of
// backed-up files. It is a pure-Go port of forensic-core's
// data/containers/android_backup.rs.
package androidbackup

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/containers/archive/tar"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// Magic is the header's first line.
	Magic = "ANDROID BACKUP\n"
	// MIUI is the MIUI wrapper's first line.
	MIUI = "MIUI BACKUP\n"
	// MaxVersion is the newest header version this reader understands.
	MaxVersion uint32 = 5
	// MaxHeaderBytes bounds the header read.
	MaxHeaderBytes = 1024
	// MaxPackedBytes and MaxUncompressedBytes bound in-memory payloads.
	MaxPackedBytes       uint64 = 256 * 1024 * 1024
	MaxUncompressedBytes uint64 = 256 * 1024 * 1024
	// AES256 is the only encryption algorithm the header may name.
	AES256 = "AES-256"
	// MaxRounds bounds PBKDF2 rounds in a header.
	MaxRounds uint32 = 10000000
	// MaxHexLineBytes bounds one hex-encoded header line.
	MaxHexLineBytes = 4096
)

// MIUIHeader is the MIUI wrapper in front of the Android header.
type MIUIHeader struct {
	Version string
	Name    string
	Flag    string
}

// EncryptionHeader is the password-protected header after an AES-256 line.
// The master-key blob is ciphertext and is never decrypted here.
type EncryptionHeader struct {
	UserSalt      []byte
	ChecksumSalt  []byte
	Rounds        uint32
	UserIV        []byte
	MasterKeyBlob []byte
}

// Header is the parsed backup header.
type Header struct {
	Version          uint32
	Compressed       bool
	Encryption       string
	EncryptionHeader *EncryptionHeader
	HeaderLen        uint64
	MIUI             *MIUIHeader
}

// Encrypted reports whether the payload is encrypted.
func (h *Header) Encrypted() bool { return h.EncryptionHeader != nil }

// Backup is a parsed, unencrypted backup with an open tar payload.
type Backup struct {
	Header  *Header
	Payload source.ByteSource
	Reader  archive.Reader
}

// MatchesHeader reports whether head begins with an Android or MIUI header.
func MatchesHeader(head []byte) bool {
	return bytes.HasPrefix(head, []byte(Magic)) || bytes.HasPrefix(head, []byte(MIUI))
}

// ParseHeader parses the text header from src.
func ParseHeader(src source.ByteSource) (*Header, error) {
	length := src.Len()
	if length == 0 {
		return nil, corrupt(0, "the backup header is truncated")
	}
	readLen := length
	if readLen > MaxHeaderBytes {
		readLen = MaxHeaderBytes
	}
	bytes, err := source.ReadVecAt(src, 0, readLen)
	if err != nil {
		return nil, err
	}
	header, consumed, err := parseHeaderBytes(bytes)
	if err != nil {
		return nil, err
	}
	header.HeaderLen = consumed
	return header, nil
}

func parseHeaderBytes(data []byte) (*Header, uint64, error) {
	position := 0
	var miui *MIUIHeader
	if bytes.HasPrefix(data, []byte(MIUI)) {
		position = len(MIUI)
		version, ok := line(data, &position)
		if !ok {
			return nil, 0, corrupt(0, "the MIUI prefix is truncated")
		}
		name, ok := line(data, &position)
		if !ok {
			return nil, 0, corrupt(0, "the MIUI prefix is truncated")
		}
		flag, ok := line(data, &position)
		if !ok {
			return nil, 0, corrupt(0, "the MIUI prefix is truncated")
		}
		miui = &MIUIHeader{Version: string(trimLine(version)), Name: string(trimLine(name)), Flag: string(trimLine(flag))}
	}
	magic, ok := line(data, &position)
	if !ok {
		return nil, 0, corrupt(uint64(position), "the backup header is truncated")
	}
	if string(trimLine(magic))+"\n" != Magic {
		if miui != nil {
			return nil, 0, unsupported("a MIUI backup (the prefix is not followed by `ANDROID BACKUP`)")
		}
		return nil, 0, unsupported("an Android backup header (the first line is not `ANDROID BACKUP`)")
	}
	versionText, ok := line(data, &position)
	if !ok {
		return nil, 0, corrupt(uint64(position), "the backup header has no version line")
	}
	var version uint32
	if _, err := fmt.Sscanf(string(trimLine(versionText)), "%d", &version); err != nil {
		return nil, 0, corrupt(uint64(position), "the backup version is not a number")
	}
	if version == 0 {
		return nil, 0, corrupt(0, "the backup header declares version 0")
	}
	if version > MaxVersion {
		return nil, 0, unsupported(fmt.Sprintf("an Android backup of version %d, newer than the supported version %d", version, MaxVersion))
	}
	compressed := false
	if version >= 2 {
		flagText, ok := line(data, &position)
		if !ok {
			return nil, 0, corrupt(uint64(position), "the backup header has no compression flag")
		}
		var flag uint32
		if _, err := fmt.Sscanf(string(trimLine(flagText)), "%d", &flag); err != nil {
			return nil, 0, corrupt(uint64(position), "the compression flag is not a number")
		}
		switch flag {
		case 0:
		case 1:
			compressed = true
		default:
			return nil, 0, corrupt(uint64(position), fmt.Sprintf("the backup header's compression flag is %d, not 0 or 1", flag))
		}
	}
	encText, ok := line(data, &position)
	if !ok {
		return nil, 0, corrupt(uint64(position), "the backup header has no encryption line")
	}
	encryption := strings.TrimSpace(string(encText))
	if encryption == "" {
		return nil, 0, corrupt(uint64(position), "the backup header's encryption line is empty")
	}
	header := &Header{Version: version, Compressed: compressed, Encryption: encryption, MIUI: miui, HeaderLen: uint64(position)}
	if strings.EqualFold(encryption, "none") {
		return header, uint64(position), nil
	}
	encHeader, err := parseEncryptionHeader(data, &position)
	if err != nil {
		return nil, 0, err
	}
	header.EncryptionHeader = encHeader
	header.HeaderLen = uint64(position)
	return header, uint64(position), nil
}

func parseEncryptionHeader(bytes []byte, position *int) (*EncryptionHeader, error) {
	userSaltLine, ok := line(bytes, position)
	if !ok {
		return nil, corrupt(uint64(*position), "the encryption header has no user salt")
	}
	checksumSaltLine, ok := line(bytes, position)
	if !ok {
		return nil, corrupt(uint64(*position), "the encryption header has no checksum salt")
	}
	roundsLine, ok := line(bytes, position)
	if !ok {
		return nil, corrupt(uint64(*position), "the encryption header has no round count")
	}
	userIVLine, ok := line(bytes, position)
	if !ok {
		return nil, corrupt(uint64(*position), "the encryption header has no user IV")
	}
	blobLine, ok := line(bytes, position)
	if !ok {
		return nil, corrupt(uint64(*position), "the encryption header has no master-key blob")
	}
	userSalt, err := decodeHexLine(userSaltLine)
	if err != nil {
		return nil, err
	}
	checksumSalt, err := decodeHexLine(checksumSaltLine)
	if err != nil {
		return nil, err
	}
	var rounds uint32
	if _, err := fmt.Sscanf(string(trimLine(roundsLine)), "%d", &rounds); err != nil || rounds > MaxRounds {
		return nil, corrupt(uint64(*position), "the encryption header's round count is invalid")
	}
	userIV, err := decodeHexLine(userIVLine)
	if err != nil {
		return nil, err
	}
	blob, err := decodeHexLine(blobLine)
	if err != nil {
		return nil, err
	}
	return &EncryptionHeader{
		UserSalt: userSalt, ChecksumSalt: checksumSalt, Rounds: rounds,
		UserIV: userIV, MasterKeyBlob: blob,
	}, nil
}

func decodeHexLine(line []byte) ([]byte, error) {
	text := strings.TrimSpace(string(line))
	if len(text) > MaxHexLineBytes {
		return nil, corrupt(0, "an encryption header line exceeds its byte limit")
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return nil, corrupt(0, "an encryption header line is not valid hex")
	}
	return decoded, nil
}

// Open parses the header and opens the tar payload. Encrypted backups are
// refused explicitly; decryption is not ported.
func Open(id source.ID, parent source.ByteSource, limits archive.Limits) (*Backup, error) {
	header, err := ParseHeader(parent)
	if err != nil {
		return nil, err
	}
	if header.Encrypted() {
		return nil, unsupported("an encrypted Android backup; password-based decryption is not ported")
	}
	payloadID := source.ID(uint64(id) + 1)
	payloadStart := header.HeaderLen
	if payloadStart > parent.Len() {
		return nil, corrupt(payloadStart, "the backup header is longer than the file")
	}
	var payload source.ByteSource
	if header.Compressed {
		packedLen := parent.Len() - payloadStart
		if packedLen > MaxPackedBytes {
			return nil, unsupported(fmt.Sprintf("a compressed backup of %d packed bytes exceeds the %d-byte limit", packedLen, MaxPackedBytes))
		}
		stream := io.NewSectionReader(readerAtAdapter{src: parent}, int64(payloadStart), int64(packedLen))
		zr, err := zlib.NewReader(stream)
		if err != nil {
			return nil, corrupt(payloadStart, fmt.Sprintf("the backup payload does not start a zlib stream: %v", err))
		}
		decoded, err := io.ReadAll(io.LimitReader(zr, int64(MaxUncompressedBytes)+1))
		closeErr := zr.Close()
		if err != nil {
			return nil, corrupt(payloadStart, fmt.Sprintf("the backup payload does not inflate: %v", err))
		}
		if closeErr != nil {
			return nil, corrupt(payloadStart, fmt.Sprintf("the backup payload does not inflate: %v", closeErr))
		}
		if uint64(len(decoded)) > MaxUncompressedBytes {
			return nil, unsupported(fmt.Sprintf("the backup inflates past the %d-byte limit", MaxUncompressedBytes))
		}
		payload = source.NewMemorySourceWithImage(payloadID, parent.ImageID(), decoded)
	} else {
		var err error
		payload, err = source.NewSubSource(payloadID, parent, payloadStart, parent.Len()-payloadStart)
		if err != nil {
			return nil, err
		}
	}
	reader, err := (tar.Adapter{}).Open(payload, limits)
	if err != nil {
		return nil, err
	}
	return &Backup{Header: header, Payload: payload, Reader: reader}, nil
}

// Entries lists the backup's tar members.
func (b *Backup) Entries() ([]archive.Entry, error) { return b.Reader.Entries() }

// OpenEntry opens one member's stream with the caller's source id.
func (b *Backup) OpenEntry(path string, id source.ID) (source.ByteSource, error) {
	return b.Reader.OpenEntry(path, id)
}

type readerAtAdapter struct{ src source.ByteSource }

func (r readerAtAdapter) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, io.EOF
	}
	offset := uint64(off)
	if offset >= r.src.Len() {
		return 0, io.EOF
	}
	n, err := r.src.ReadAt(offset, p)
	if err != nil {
		return n, err
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func line(bytes []byte, position *int) ([]byte, bool) {
	if *position >= len(bytes) {
		return nil, false
	}
	start := *position
	for *position < len(bytes) && bytes[*position] != '\n' {
		*position = *position + 1
	}
	if *position >= len(bytes) {
		return nil, false
	}
	line := bytes[start:*position]
	*position++
	return line, true
}

func trimLine(line []byte) []byte { return bytes.TrimRight(line, "\r") }

func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}
