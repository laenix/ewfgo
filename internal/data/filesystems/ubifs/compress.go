package ubifs

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"

	zstd "github.com/laenix/ewfgo/internal/data/filesystems/ubifs/zstd"
)

// Compression names, as UBIFS numbers them.
const (
	CompressionNone uint16 = 0
	CompressionLZO  uint16 = 1
	CompressionZLIB uint16 = 2
	CompressionZSTD uint16 = 3
	CompressionLZ4  uint16 = 4
)

// CompressionName returns the compressor's UBIFS name.
func CompressionName(compression uint16) string {
	switch compression {
	case CompressionNone:
		return "none"
	case CompressionLZO:
		return "lzo"
	case CompressionZLIB:
		return "zlib"
	case CompressionZSTD:
		return "zstd"
	case CompressionLZ4:
		return "lz4"
	default:
		return "unknown"
	}
}

func compressionName(compression uint16) string { return CompressionName(compression) }

func compressionSupported(compression uint16) bool {
	return compression <= CompressionLZ4
}

// decodeUBIFSBlock decodes one data node's payload to exactly size bytes.  The
// node length includes alignment padding, so the payload is tried as stored
// and then with up to seven trailing zero bytes removed.
func decodeUBIFSBlock(compression uint16, stored []byte, size int) ([]byte, error) {
	if size < 0 || size > MaxDecodedBlock {
		return nil, corruptf("data node declares %d bytes, past the %d-byte block bound", size, MaxDecodedBlock)
	}
	if compression == CompressionNone {
		if len(stored) < size {
			return nil, corruptf("uncompressed data node stores %d bytes for a %d-byte block", len(stored), size)
		}
		return append([]byte(nil), stored[:size]...), nil
	}
	candidates := make([][]byte, 0, 8)
	candidates = append(candidates, stored)
	trimmed := stored
	for count := 0; count < 7; count++ {
		if len(trimmed) == 0 || trimmed[len(trimmed)-1] != 0 {
			break
		}
		trimmed = trimmed[:len(trimmed)-1]
		candidates = append(candidates, trimmed)
	}
	var lastError error
	for _, candidate := range candidates {
		decoded, err := decompress(compression, candidate, size)
		if err != nil {
			lastError = err
			continue
		}
		if len(decoded) == size {
			return decoded, nil
		}
		lastError = corruptf("decoded %d bytes for a block declared as %d", len(decoded), size)
	}
	if lastError == nil {
		lastError = corruptf("no candidate payload")
	}
	return nil, corruptf("%s block did not decode to %d bytes: %v", compressionName(compression), size, lastError)
}

func decompress(compression uint16, input []byte, limit int) ([]byte, error) {
	switch compression {
	case CompressionLZO:
		return decompressLZO(input, limit)
	case CompressionZLIB:
		return decompressZlib(input, limit)
	case CompressionZSTD:
		return decompressZstd(input, limit)
	case CompressionLZ4:
		return decompressLZ4(input, limit)
	default:
		return nil, unsupportedf("compression type %d (%s) is not decoded by this reader",
			compression, compressionName(compression))
	}
}

func decompressZlib(input []byte, limit int) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(input))
	if err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	defer reader.Close()
	out, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	if len(out) > limit {
		return nil, fmt.Errorf("zlib: decoded output passes the %d-byte bound", limit)
	}
	return out, nil
}

func decompressZstd(input []byte, limit int) ([]byte, error) {
	reader := zstd.NewReader(bytes.NewReader(input))
	out, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("zstd: %w", err)
	}
	if len(out) > limit {
		return nil, fmt.Errorf("zstd: decoded output passes the %d-byte bound", limit)
	}
	return out, nil
}

// decompressLZ4 decodes one raw LZ4 block, refusing output past limit.
func decompressLZ4(input []byte, limit int) ([]byte, error) {
	out := make([]byte, 0, limit)
	at := 0
	for at < len(input) {
		token := input[at]
		at++
		literals := int(token >> 4)
		if literals == 15 {
			for {
				if at >= len(input) {
					return nil, fmt.Errorf("lz4: the block ends inside a literal-length run")
				}
				value := input[at]
				at++
				literals += int(value)
				if value != 255 {
					break
				}
			}
		}
		if literals > 0 {
			if literals > len(input)-at {
				return nil, fmt.Errorf("lz4: the block ends inside a literal run")
			}
			if len(out)+literals > limit {
				return nil, fmt.Errorf("lz4: decoded output passes the %d-byte bound", limit)
			}
			out = append(out, input[at:at+literals]...)
			at += literals
		}
		if at >= len(input) {
			break
		}
		if at+2 > len(input) {
			return nil, fmt.Errorf("lz4: the block ends before a match offset")
		}
		offset := int(uint16(input[at]) | uint16(input[at+1])<<8)
		at += 2
		if offset == 0 || offset > len(out) {
			return nil, fmt.Errorf("lz4: a match offset %d reaches before the decoded bytes", offset)
		}
		length := int(token & 0x0f)
		if length == 15 {
			for {
				if at >= len(input) {
					return nil, fmt.Errorf("lz4: the block ends inside a match-length run")
				}
				value := input[at]
				at++
				length += int(value)
				if value != 255 {
					break
				}
			}
		}
		length += 4
		if len(out)+length > limit {
			return nil, fmt.Errorf("lz4: decoded output passes the %d-byte bound", limit)
		}
		for index := 0; index < length; index++ {
			out = append(out, out[len(out)-offset])
		}
	}
	return out, nil
}

// decompressLZO decodes one raw LZO1X block.  The implementation follows the
// reference reader's pure-Rust LZO1X decoder: every back-reference is checked,
// the end marker must be canonical, and trailing bytes are refused.
func decompressLZO(input []byte, limit int) ([]byte, error) {
	if limit < 0 {
		return nil, fmt.Errorf("lzo: negative output bound")
	}
	dst := make([]byte, limit)
	n, err := lzoDecompressInto(input, dst)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func lzoDecompressInto(src, dst []byte) (int, error) {
	if len(src) < 3 {
		return 0, fmt.Errorf("lzo: compressed input ended prematurely")
	}
	ip, op := 0, 0
	state, t := 0, 0
	if first := src[0]; first > 17 {
		ip = 1
		t = int(first) - 17
		if err := lzoCopyLiterals(src, &ip, dst, &op, t); err != nil {
			return 0, err
		}
		if t < 4 {
			state = t
		} else {
			state = 4
		}
	}
	for {
		value, err := lzoRead(src, &ip)
		if err != nil {
			return 0, err
		}
		t = int(value)
		var distance, length, next int
		switch {
		case t < 16:
			if state == 0 {
				var run int
				if t == 0 {
					extension, err := lzoLengthExt(src, &ip)
					if err != nil {
						return 0, err
					}
					run = lzoSaturatingAdd(extension, 18)
				} else {
					run = t + 3
				}
				if err := lzoCopyLiterals(src, &ip, dst, &op, run); err != nil {
					return 0, err
				}
				state = 4
				continue
			}
			next = t & 3
			follow, err := lzoRead(src, &ip)
			if err != nil {
				return 0, err
			}
			if state == 4 {
				distance = 1 + 2048 + (t >> 2) + (int(follow) << 2)
				length = 3
			} else {
				distance = 1 + (t >> 2) + (int(follow) << 2)
				length = 2
			}
		case t >= 64:
			next = t & 3
			follow, err := lzoRead(src, &ip)
			if err != nil {
				return 0, err
			}
			distance = 1 + ((t >> 2) & 7) + (int(follow) << 3)
			length = (t >> 5) + 1
		case t >= 32:
			if t&31 == 0 {
				extension, err := lzoLengthExt(src, &ip)
				if err != nil {
					return 0, err
				}
				length = lzoSaturatingAdd(extension, 33)
			} else {
				length = (t & 31) + 2
			}
			d, err := lzoRead16(src, &ip)
			if err != nil {
				return 0, err
			}
			distance = 1 + (d >> 2)
			next = d & 3
		default:
			hi := (t & 8) << 11
			if t&7 == 0 {
				extension, err := lzoLengthExt(src, &ip)
				if err != nil {
					return 0, err
				}
				length = lzoSaturatingAdd(extension, 9)
			} else {
				length = (t & 7) + 2
			}
			d, err := lzoRead16(src, &ip)
			if err != nil {
				return 0, err
			}
			distPart := d >> 2
			next = d & 3
			if hi == 0 && distPart == 0 {
				if length != 3 {
					return 0, fmt.Errorf("lzo: malformed end marker")
				}
				if ip < len(src) {
					return 0, fmt.Errorf("lzo: trailing bytes after end-of-stream")
				}
				return op, nil
			}
			distance = hi + distPart + 0x4000
		}
		if err := lzoCopyMatch(dst, &op, distance, length); err != nil {
			return 0, err
		}
		if err := lzoCopyLiterals(src, &ip, dst, &op, next); err != nil {
			return 0, err
		}
		state = next
	}
}

func lzoRead(src []byte, ip *int) (byte, error) {
	if *ip >= len(src) {
		return 0, fmt.Errorf("lzo: compressed input ended prematurely")
	}
	value := src[*ip]
	*ip++
	return value, nil
}

func lzoRead16(src []byte, ip *int) (int, error) {
	low, err := lzoRead(src, ip)
	if err != nil {
		return 0, err
	}
	high, err := lzoRead(src, ip)
	if err != nil {
		return 0, err
	}
	return int(low) | int(high)<<8, nil
}

func lzoLengthExt(src []byte, ip *int) (int, error) {
	zeros := 0
	for {
		if *ip >= len(src) {
			return 0, fmt.Errorf("lzo: compressed input ended prematurely")
		}
		if src[*ip] != 0 {
			break
		}
		*ip++
		zeros++
	}
	term, err := lzoRead(src, ip)
	if err != nil {
		return 0, err
	}
	return lzoSaturatingAdd(lzoSaturatingMul(zeros, 255), int(term)), nil
}

func lzoCopyLiterals(src []byte, ip *int, dst []byte, op *int, count int) error {
	if count < 0 || *op > len(dst) || count > len(dst)-*op {
		return fmt.Errorf("lzo: output buffer too small")
	}
	if count < 0 || *ip > len(src) || count > len(src)-*ip {
		return fmt.Errorf("lzo: compressed input ended prematurely")
	}
	copy(dst[*op:*op+count], src[*ip:*ip+count])
	*op += count
	*ip += count
	return nil
}

func lzoCopyMatch(dst []byte, op *int, distance, length int) error {
	if distance <= 0 || *op < distance {
		return fmt.Errorf("lzo: back-reference before output start")
	}
	if length < 0 || *op > len(dst) || length > len(dst)-*op {
		return fmt.Errorf("lzo: output buffer too small")
	}
	start := *op - distance
	for index := 0; index < length; index++ {
		dst[*op+index] = dst[start+index]
	}
	*op += length
	return nil
}

func lzoSaturatingAdd(left, right int) int {
	if left > int(^uint(0)>>1)-right {
		return int(^uint(0) >> 1)
	}
	return left + right
}

func lzoSaturatingMul(left, right int) int {
	if left == 0 || right == 0 {
		return 0
	}
	maxInt := int(^uint(0) >> 1)
	if left > maxInt/right {
		return maxInt
	}
	return left * right
}
