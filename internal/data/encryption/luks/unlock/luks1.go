package unlock

// LUKS1 unlock.
//
// The 592-byte header names the cipher, the mode, the PBKDF2 hash, the payload
// offset in 512-byte sectors, the master-key size, the master-key digest and
// its salt/iteration count, and eight 48-byte key-slot descriptors. Each
// descriptor gives the slot's PBKDF2 iterations, its 32-byte salt, the
// absolute sector where its encrypted stripe area begins, and the stripe
// count.

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/encryption/luks"
	"github.com/laenix/ewfgo/internal/data/source"
)

type luks1Slot struct {
	index      int
	active     bool
	iterations uint32
	salt       []byte
	areaSector uint64
	stripes    uint32
}

type luks1Header struct {
	cipher           string
	mode             string
	hash             string
	payloadOffset    uint64
	keyBytes         int
	digest           []byte
	digestSalt       []byte
	digestIterations uint32
	slots            []luks1Slot
}

func readLUKS1Header(src source.ByteSource) (*luks1Header, error) {
	if src.Len() < uint64(luks.LUKS1HeaderBytes) {
		return nil, truncated(uint64(luks.LUKS1HeaderBytes), src.Len())
	}
	head, err := source.ReadVecAt(src, 0, uint64(luks.LUKS1HeaderBytes))
	if err != nil {
		return nil, readError(err)
	}
	if !bytes.HasPrefix(head, []byte(luks.Magic)) {
		return nil, ErrNotLUKS
	}
	if version := binary.BigEndian.Uint16(head[6:8]); version != 1 {
		return nil, fmt.Errorf("%w: LUKS%d is not LUKS1", ErrUnsupportedVersion, version)
	}
	keyBytes64 := binary.BigEndian.Uint32(head[0x6c:])
	header := &luks1Header{
		cipher:           luks1String(head, 0x08, 32),
		mode:             luks1String(head, 0x28, 32),
		hash:             luks1String(head, 0x48, 32),
		payloadOffset:    uint64(binary.BigEndian.Uint32(head[0x68:])) * DMSectorBytes,
		keyBytes:         int(keyBytes64),
		digest:           append([]byte(nil), head[0x70:0x84]...),
		digestSalt:       append([]byte(nil), head[0x84:0xa4]...),
		digestIterations: binary.BigEndian.Uint32(head[0xa4:]),
		slots:            make([]luks1Slot, 0, luks.LUKS1Keyslots),
	}
	for index := 0; index < luks.LUKS1Keyslots; index++ {
		base := 0xd0 + index*luks.LUKS1KeyslotBytes
		slot := luks1Slot{index: index}
		if binary.BigEndian.Uint32(head[base:]) == luks.LUKS1KeyslotActive {
			slot.active = true
			slot.iterations = binary.BigEndian.Uint32(head[base+4:])
			slot.salt = append([]byte(nil), head[base+8:base+8+32]...)
			slot.areaSector = uint64(binary.BigEndian.Uint32(head[base+40:]))
			slot.stripes = binary.BigEndian.Uint32(head[base+44:])
		}
		header.slots = append(header.slots, slot)
	}
	return header, nil
}

func unlockLUKS1(src source.ByteSource, passphrase []byte) (*Unlocked, error) {
	header, err := readLUKS1Header(src)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(header.cipher, "aes") {
		return nil, fmt.Errorf("%w: cipher %q", ErrUnsupportedCipher, header.cipher)
	}
	spec, err := parseEncryption(header.cipher + "-" + header.mode)
	if err != nil {
		return nil, err
	}
	hash, ok := pbkdf2HashByName(header.hash, true)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedHash, header.hash)
	}
	if !spec.acceptsKey(header.keyBytes) {
		return nil, fmt.Errorf("%w: %d bytes with %s", ErrKeyBytes, header.keyBytes, spec.name)
	}
	if header.payloadOffset > src.Len() {
		return nil, fmt.Errorf("%w: payload offset %d past the source's %d bytes",
			ErrGeometry, header.payloadOffset, src.Len())
	}
	if allZero(header.digest) || allZero(header.digestSalt) || header.digestIterations == 0 {
		return nil, ErrNoDigest
	}
	if uint64(header.digestIterations) > MaxKDFIterations {
		return nil, fmt.Errorf("%w: the master-key digest uses %d iterations, limit %d",
			ErrIterations, header.digestIterations, MaxKDFIterations)
	}
	active := 0
	for _, slot := range header.slots {
		if slot.active {
			active++
		}
	}
	if active == 0 {
		return nil, ErrNoActiveKeyslot
	}

	var tried []int
	for _, slot := range header.slots {
		if !slot.active {
			continue
		}
		tried = append(tried, slot.index)
		if uint64(slot.iterations) == 0 || uint64(slot.iterations) > MaxKDFIterations {
			return nil, fmt.Errorf("%w: key slot %d declares %d iterations, limit %d",
				ErrIterations, slot.index, slot.iterations, MaxKDFIterations)
		}
		if slot.stripes == 0 || uint64(slot.stripes) > MaxStripes {
			return nil, fmt.Errorf("%w: key slot %d declares %d stripes (1..=%d allowed)",
				ErrStripes, slot.index, slot.stripes, MaxStripes)
		}
		if slot.areaSector > ^uint64(0)/DMSectorBytes {
			return nil, fmt.Errorf("%w: key slot %d area offset overflows", ErrGeometry, slot.index)
		}
		areaOffset := slot.areaSector * DMSectorBytes
		needed := uint64(header.keyBytes) * uint64(slot.stripes)
		needed = (needed + DMSectorBytes - 1) / DMSectorBytes * DMSectorBytes
		if needed > MaxAreaBytes {
			return nil, fmt.Errorf("%w: key slot %d area needs %d bytes, limit %d",
				ErrGeometry, slot.index, needed, MaxAreaBytes)
		}
		if areaOffset > src.Len() || needed > src.Len()-areaOffset {
			return nil, fmt.Errorf("%w: key slot %d needs [%d, %d) but the source holds %d bytes",
				ErrKeyslotOutside, slot.index, areaOffset, areaOffset+needed, src.Len())
		}
		slotKey, err := pbkdf2Key(hash.new, passphrase, slot.salt, slot.iterations, header.keyBytes)
		if err != nil {
			return nil, fmt.Errorf("key slot %d: %w", slot.index, err)
		}
		area, err := source.ReadVecAt(src, areaOffset, needed)
		if err != nil {
			zeroBytes(slotKey)
			return nil, readError(err)
		}
		areaCipher, err := newSectorCipher(spec, slotKey)
		if err != nil {
			zeroBytes(slotKey)
			return nil, fmt.Errorf("key slot %d: %w", slot.index, err)
		}
		if err := decryptArea(areaCipher, area, areaOffset); err != nil {
			zeroBytes(slotKey)
			return nil, fmt.Errorf("key slot %d: %w", slot.index, err)
		}
		zeroBytes(slotKey)
		candidate, err := afMerge(area[:uint64(header.keyBytes)*uint64(slot.stripes)], header.keyBytes)
		zeroBytes(area)
		if err != nil {
			return nil, fmt.Errorf("key slot %d: %w", slot.index, err)
		}
		computed, err := pbkdf2Key(hash.new, candidate, header.digestSalt, header.digestIterations, LUKS1DigestBytes)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(computed, header.digest) != 1 {
			zeroBytes(candidate)
			continue
		}
		payloadLen := src.Len() - header.payloadOffset
		return &Unlocked{
			Version:       1,
			Keyslot:       slot.index,
			KDF:           "pbkdf2",
			Cipher:        "aes",
			Mode:          spec.name,
			KeyBytes:      header.keyBytes,
			Stripes:       uint64(slot.stripes),
			Iterations:    uint64(slot.iterations),
			AreaOffset:    areaOffset,
			PayloadOffset: header.payloadOffset,
			PayloadLen:    payloadLen,
			IVTweak:       0,
			segments: []segmentPlan{{
				index:          0,
				logicalOffset:  0,
				physicalOffset: header.payloadOffset,
				size:           payloadLen,
				ivTweak:        0,
				sectorSize:     uint32(DMSectorBytes),
				spec:           spec,
				encryption:     header.cipher + "-" + header.mode,
			}},
			masterKey: candidate,
		}, nil
	}
	return nil, fmt.Errorf("%w: tried key slots %v", ErrWrongPassphrase, tried)
}

func luks1String(head []byte, offset, width int) string {
	if offset < 0 || width <= 0 || offset+width > len(head) {
		return ""
	}
	field := head[offset : offset+width]
	end := bytes.IndexByte(field, 0)
	if end < 0 {
		end = width
	}
	if end == 0 || !utf8.Valid(field[:end]) {
		return ""
	}
	return strings.TrimSpace(string(field[:end]))
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
