package unlock

import (
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/encryption/luks"
	"github.com/laenix/ewfgo/internal/data/source"
)

func TestReadLUKS2MetadataDecodesTheRecords(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(1024, 1))
	image := buildLUKS2(t, options)
	metadata, err := readLUKS2Metadata(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("readLUKS2Metadata: %v", err)
	}
	if metadata.headerSize != 12288 || metadata.headerOffset != 0 {
		t.Fatalf("header = %+v", metadata)
	}
	if len(metadata.keyslots) != 1 {
		t.Fatalf("keyslots = %d", len(metadata.keyslots))
	}
	slot := metadata.keyslots[0]
	if slot.index != 0 || slot.kind != "luks2" || slot.keySize != 32 ||
		slot.stripes != 4 || slot.afHash != "sha256" {
		t.Fatalf("key slot = %+v", slot)
	}
	if slot.area.kind != "raw" || slot.area.offset != 16384 ||
		slot.area.size != 512 || slot.area.keySize != 64 ||
		slot.area.encryption != "aes-xts-plain64" {
		t.Fatalf("area = %+v", slot.area)
	}
	if slot.kdf.kind != "pbkdf2" || slot.kdf.hash != "sha256" || slot.kdf.iterations != 1000 {
		t.Fatalf("kdf = %+v", slot.kdf)
	}
	if len(slot.kdf.salt) != 32 {
		t.Fatalf("salt = %d bytes", len(slot.kdf.salt))
	}
	if len(metadata.digests) != 1 || metadata.digests[0].kind != "pbkdf2" ||
		len(metadata.digests[0].keyslots) != 1 || metadata.digests[0].keyslots[0] != 0 ||
		len(metadata.digests[0].salt) != 32 || len(metadata.digests[0].digest) != 32 {
		t.Fatalf("digest = %+v", metadata.digests)
	}
	if len(metadata.segments) != 1 {
		t.Fatalf("segments = %d", len(metadata.segments))
	}
	segment := metadata.segments[0]
	if segment.offset != 32768 || !segment.hasSize || segment.size != 1024 ||
		segment.ivTweak != 9 || segment.sectorSize != 512 ||
		segment.encryption != "aes-xts-plain64" {
		t.Fatalf("segment = %+v", segment)
	}
}

func TestReadLUKS2MetadataKeepsAnUnknownKDFByName(t *testing.T) {
	document := `{"keyslots":{"0":{"type":"luks2","key_size":32,
      "kdf":{"type":"scrypt"},
      "af":{"stripes":4,"hash":"sha256"},
      "area":{"type":"raw","offset":"8192","size":"512","encryption":"aes-xts-plain64","key_size":64}}},
      "segments":{}}`
	image := buildLUKS2Header(12288, document, 0)
	metadata, err := readLUKS2Metadata(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.keyslots[0].kdf.kind != "scrypt" {
		t.Fatalf("kdf = %+v", metadata.keyslots[0].kdf)
	}
	if len(metadata.digests) != 0 || len(metadata.segments) != 0 {
		t.Fatalf("unexpected records: %+v", metadata)
	}
}

func TestReadLUKS2MetadataDefaults(t *testing.T) {
	document := `{"keyslots":{"0":{"type":"luks2","key_size":32,
      "kdf":{"type":"pbkdf2","hash":"sha256","iterations":"1000","salt":"c29tZXNhbHQ="},
      "af":{"stripes":"3"},
      "area":{"type":"raw","offset":8192,"size":512,"encryption":"aes-xts-plain64"}}},
      "segments":{"0":{"type":"crypt","offset":32768,"size":"dynamic","encryption":"aes-xts-plain64"}}}`
	image := buildLUKS2Header(12288, document, 0)
	metadata, err := readLUKS2Metadata(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatal(err)
	}
	slot := metadata.keyslots[0]
	if slot.afHash != "sha256" || slot.area.keySize != 32 || slot.stripes != 3 ||
		slot.kdf.hash != "sha256" || slot.kdf.iterations != 1000 {
		t.Fatalf("slot defaults = %+v", slot)
	}
	segment := metadata.segments[0]
	if segment.hasSize || segment.ivTweak != 0 || segment.sectorSize != 512 {
		t.Fatalf("segment defaults = %+v", segment)
	}
}

func TestReadLUKS2MetadataRefusals(t *testing.T) {
	valid := buildLUKS2(t, defaultLUKS2Options(patternBytes(512, 1)))

	t.Run("truncated binary header", func(t *testing.T) {
		_, err := readLUKS2Metadata(source.NewMemorySource(1, valid[:100]))
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("truncated declared header", func(t *testing.T) {
		_, err := readLUKS2Metadata(source.NewMemorySource(1, valid[:5000]))
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("header size below the binary header", func(t *testing.T) {
		image := append([]byte(nil), valid...)
		putBE64(image, 8, 1024)
		_, err := readLUKS2Metadata(source.NewMemorySource(1, image))
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("header size above the limit", func(t *testing.T) {
		image := append([]byte(nil), valid...)
		putBE64(image, 8, luks.MaxHeaderBytes+1)
		_, err := readLUKS2Metadata(source.NewMemorySource(1, image))
		if !errors.Is(err, ErrHeaderTooLarge) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("detached header offset", func(t *testing.T) {
		image := buildLUKS2(t, func() luks2Options {
			options := defaultLUKS2Options(patternBytes(512, 1))
			options.hdrOffset = 4096
			return options
		}())
		_, err := readLUKS2Metadata(source.NewMemorySource(1, image))
		if !errors.Is(err, ErrDetachedHeader) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("not LUKS", func(t *testing.T) {
		_, err := readLUKS2Metadata(source.NewMemorySource(1, make([]byte, 8192)))
		if !errors.Is(err, ErrNotLUKS) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("malformed JSON", func(t *testing.T) {
		image := buildLUKS2Header(12288, `{"keyslots":`, 0)
		_, err := readLUKS2Metadata(source.NewMemorySource(1, image))
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("empty metadata area", func(t *testing.T) {
		image := buildLUKS2Header(12288, "", 0)
		_, err := readLUKS2Metadata(source.NewMemorySource(1, image))
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("missing keyslots", func(t *testing.T) {
		image := buildLUKS2Header(12288, `{"segments":{}}`, 0)
		_, err := readLUKS2Metadata(source.NewMemorySource(1, image))
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("non-numeric keyslot name", func(t *testing.T) {
		for _, name := range []string{"first", "-1", "+1", "1.0"} {
			document := `{"keyslots":{"` + name + `":{"type":"luks2","key_size":32,
              "kdf":{"type":"pbkdf2","iterations":1,"salt":"c29tZXNhbHQ="},
              "af":{"stripes":2},
              "area":{"type":"raw","offset":"4096","size":"512","encryption":"aes-xts-plain64"}}}}`
			_, err := readLUKS2Metadata(source.NewMemorySource(1, buildLUKS2Header(12288, document, 0)))
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("keyslot name %q: error = %v", name, err)
			}
		}
	})
	t.Run("non-numeric segment name", func(t *testing.T) {
		document := `{"keyslots":{},"segments":{"first":{"type":"crypt","offset":4096,
          "size":"dynamic","encryption":"aes-xts-plain64"}}}`
		_, err := readLUKS2Metadata(source.NewMemorySource(1, buildLUKS2Header(12288, document, 0)))
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("bad base64 salt", func(t *testing.T) {
		document := `{"keyslots":{"0":{"type":"luks2","key_size":32,
          "kdf":{"type":"pbkdf2","iterations":1,"salt":"not base64!"},
          "af":{"stripes":2},
          "area":{"type":"raw","offset":"4096","size":"512","encryption":"aes-xts-plain64"}}}}`
		_, err := readLUKS2Metadata(source.NewMemorySource(1, buildLUKS2Header(12288, document, 0)))
		if !errors.Is(err, ErrBadBase64) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("missing key size", func(t *testing.T) {
		document := `{"keyslots":{"0":{"type":"luks2",
          "kdf":{"type":"pbkdf2","iterations":1,"salt":"c29tZXNhbHQ="},
          "af":{"stripes":2},
          "area":{"type":"raw","offset":"4096","size":"512","encryption":"aes-xts-plain64"}}}}`
		_, err := readLUKS2Metadata(source.NewMemorySource(1, buildLUKS2Header(12288, document, 0)))
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("error = %v", err)
		}
	})
}

// The description-only LUKS2 header in the fixture corpus records a digest
// with only a type, hash and iteration count: no keyslots, salt or digest.
// Such a record can confirm nothing, so decoding must not refuse the whole
// document (the failure was "the digest salt is missing").
func TestReadLUKS2MetadataSkipsADigestThatNamesNoKeyslot(t *testing.T) {
	const document = `{
	  "keyslots": {
	    "0": {
	      "type": "luks2",
	      "key_size": 32,
	      "kdf": {"type": "pbkdf2", "hash": "sha256", "iterations": 1,
	              "salt": "c29tZXNhbHQ="},
	      "af": {"type": "luks1", "stripes": 2, "hash": "sha256"},
	      "area": {"type": "raw", "offset": "12288", "size": "512",
	               "encryption": "aes-xts-plain64", "key_size": 32}
	    }
	  },
	  "segments": {"0": {"type": "crypt", "offset": "16384", "size": "dynamic",
	                     "encryption": "aes-xts-plain64", "sector_size": 512}},
	  "digests": {"0": {"type": "pbkdf2", "hash": "sha256", "iterations": 400000}}
	}`
	image := buildLUKS2Header(12288, document, 0)
	metadata, err := readLUKS2Metadata(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("readLUKS2Metadata: %v", err)
	}
	if len(metadata.keyslots) != 1 || len(metadata.segments) != 1 {
		t.Fatalf("metadata = %+v", metadata)
	}
	if len(metadata.digests) != 0 {
		t.Fatalf("digests = %+v, want none that can confirm a slot", metadata.digests)
	}
}

// A digest that does name a key slot is the check that accepts or rejects a
// candidate master key; a partial one must still be refused rather than
// silently dropped, so a volume can never be opened without verification.
func TestReadLUKS2MetadataRefusesAPartialDigestThatNamesAKeyslot(t *testing.T) {
	const document = `{
	  "keyslots": {
	    "0": {
	      "type": "luks2",
	      "key_size": 32,
	      "kdf": {"type": "pbkdf2", "hash": "sha256", "iterations": 1,
	              "salt": "c29tZXNhbHQ="},
	      "af": {"type": "luks1", "stripes": 2, "hash": "sha256"},
	      "area": {"type": "raw", "offset": "12288", "size": "512",
	               "encryption": "aes-xts-plain64", "key_size": 32}
	    }
	  },
	  "segments": {"0": {"type": "crypt", "offset": "16384", "size": "dynamic",
	                     "encryption": "aes-xts-plain64", "sector_size": 512}},
	  "digests": {"0": {"type": "pbkdf2", "keyslots": ["0"], "hash": "sha256",
	                    "iterations": 400000}}
	}`
	image := buildLUKS2Header(12288, document, 0)
	_, err := readLUKS2Metadata(source.NewMemorySource(1, image))
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
}

func TestReadLUKS1Header(t *testing.T) {
	options := defaultLUKS1Options(patternBytes(512, 3))
	image := buildLUKS1(t, options)
	header, err := readLUKS1Header(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatal(err)
	}
	if header.cipher != "aes" || header.mode != "xts-plain64" || header.hash != "sha256" ||
		header.keyBytes != 32 || header.payloadOffset != 40*512 {
		t.Fatalf("header = %+v", header)
	}
	if len(header.digest) != 20 || len(header.digestSalt) != 32 ||
		header.digestIterations != 100 || allZero(header.digest) {
		t.Fatalf("digest fields = %+v", header)
	}
	if len(header.slots) != 8 || !header.slots[0].active || header.slots[0].stripes != 4 ||
		header.slots[0].areaSector != 8 || header.slots[0].iterations != 1000 {
		t.Fatalf("slot 0 = %+v", header.slots[0])
	}
	if header.slots[1].active {
		t.Fatal("slot 1 is active without a marker")
	}
}

func TestPlanSegmentsConcatenatesAContiguousLayout(t *testing.T) {
	segments := []luks2Segment{
		{index: 0, kind: "crypt", offset: 8192, size: 4096, hasSize: true, ivTweak: 0, sectorSize: 512, encryption: "aes-xts-plain64"},
		{index: 1, kind: "crypt", offset: 12288, size: 2048, hasSize: true, ivTweak: 8, sectorSize: 1024, encryption: "aes-xts-plain64"},
		{index: 2, kind: "crypt", offset: 14336, ivTweak: 10, sectorSize: 4096, encryption: "aes-xts-plain64"},
	}
	plans, err := planSegments(segments, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 3 {
		t.Fatalf("plans = %d", len(plans))
	}
	if plans[0].logicalOffset != 0 || plans[0].physicalOffset != 8192 || plans[0].size != 4096 {
		t.Fatalf("plan 0 = %+v", plans[0])
	}
	if plans[1].logicalOffset != 4096 || plans[1].ivTweak != 8 || plans[1].sectorSize != 1024 {
		t.Fatalf("plan 1 = %+v", plans[1])
	}
	if plans[2].logicalOffset != 6144 || plans[2].size != (1<<20)-14336 {
		t.Fatalf("plan 2 = %+v", plans[2])
	}
}

func TestPlanSegmentsRefusals(t *testing.T) {
	base := luks2Segment{index: 0, kind: "crypt", offset: 8192, size: 4096, hasSize: true, sectorSize: 512, encryption: "aes-xts-plain64"}
	cases := []struct {
		name     string
		segments []luks2Segment
		want     error
	}{
		{"empty", nil, ErrGeometry},
		{"not crypt", []luks2Segment{func() luks2Segment { s := base; s.kind = "linear"; return s }()}, ErrUnsupportedSegment},
		{"unknown cipher", []luks2Segment{func() luks2Segment { s := base; s.encryption = "serpent-xts-plain64"; return s }()}, ErrUnsupportedCipher},
		{"bad sector size", []luks2Segment{func() luks2Segment { s := base; s.sectorSize = 1000; return s }()}, ErrUnsupportedSectorSize},
		{"zero size", []luks2Segment{func() luks2Segment { s := base; s.size = 0; return s }()}, ErrSegmentLayout},
		{"outside", []luks2Segment{func() luks2Segment { s := base; s.offset = (1 << 20) + 1; s.hasSize = false; return s }()}, ErrSegmentOutside},
		{"overlap", []luks2Segment{base, func() luks2Segment { s := base; s.index = 1; s.offset = 10000; s.hasSize = false; return s }()}, ErrSegmentLayout},
		{"gap", []luks2Segment{base, func() luks2Segment { s := base; s.index = 1; s.offset = 20000; s.hasSize = false; return s }()}, ErrSegmentLayout},
		{"tweak overflow", []luks2Segment{func() luks2Segment { s := base; s.ivTweak = ^uint64(0); return s }()}, ErrSegmentLayout},
		{"dynamic before last", []luks2Segment{
			func() luks2Segment { s := base; s.hasSize = false; return s }(),
			func() luks2Segment { s := base; s.index = 1; s.offset = 12288; s.hasSize = false; return s }(),
		}, ErrSegmentLayout},
	}
	for _, test := range cases {
		_, err := planSegments(test.segments, 1<<20)
		if !errors.Is(err, test.want) {
			t.Fatalf("%s: error = %v, want %v", test.name, err, test.want)
		}
	}
	for _, size := range []uint32{512, 1024, 2048, 4096} {
		segment := base
		segment.sectorSize = size
		segment.hasSize = false
		if _, err := planSegments([]luks2Segment{segment}, 1<<20); err != nil {
			t.Fatalf("sector size %d: %v", size, err)
		}
	}
}
