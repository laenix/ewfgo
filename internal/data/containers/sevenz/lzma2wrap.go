package sevenz

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// decodeLZMA2Folder decodes one 7z LZMA2 coder.  The coder's single property
// byte is the dictionary-size property; the chunks carry their own LZMA
// properties.
func decodeLZMA2Folder(offset uint64, property byte, stored []byte, unpack uint64, maxDecoded uint64) ([]byte, error) {
	if unpack > maxDecoded {
		return nil, source.NewCorrupt(offset, fmt.Sprintf(
			"7z LZMA2 stream declares %d bytes, past the configured %d-byte budget",
			unpack, maxDecoded))
	}
	dictionary := lzma2DictSize(property)
	var out []byte
	if _, _, err := decodeLZMA2(stored, dictionary, unpack, &out, offset, unpack, true); err != nil {
		return nil, err
	}
	if uint64(len(out)) != unpack {
		return nil, source.NewCorrupt(offset, fmt.Sprintf(
			"7z LZMA2 stream decoded %d bytes but the folder declares %d",
			len(out), unpack))
	}
	return out, nil
}

func corruptAt(offset uint64, format string, args ...any) error {
	return source.NewCorrupt(offset, fmt.Sprintf(format, args...))
}

func unsupported(format string, args ...any) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: fmt.Sprintf(format, args...)}
}
