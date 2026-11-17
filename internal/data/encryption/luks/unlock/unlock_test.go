package unlock

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestUnlockLUKS2PBKDF2(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(1024, 1))
	image := buildLUKS2(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if unlocked.Version != 2 || unlocked.Keyslot != 0 || unlocked.KDF != "pbkdf2" {
		t.Fatalf("identity = %+v", unlocked)
	}
	if unlocked.CipherMode() != "aes-xts-plain64" || unlocked.KeyBytes != 32 {
		t.Fatalf("cipher = %q, key = %d", unlocked.CipherMode(), unlocked.KeyBytes)
	}
	if unlocked.PayloadOffset != 32768 || unlocked.PayloadLen != 1024 || unlocked.IVTweak != 9 {
		t.Fatalf("payload = %+v", unlocked)
	}
	if unlocked.Stripes != 4 || unlocked.Iterations != 1000 || unlocked.AreaOffset != 16384 {
		t.Fatalf("slot = %+v", unlocked)
	}
	if !bytes.Equal(unlocked.MasterKey(), options.masterKey) {
		t.Fatalf("master key = %x, want %x", unlocked.MasterKey(), options.masterKey)
	}
	if unlocked.Label() != "LUKS2 pbkdf2 (key slot 0)" {
		t.Fatalf("label = %q", unlocked.Label())
	}
}

func TestUnlockLUKS2Argon2Variants(t *testing.T) {
	for _, kind := range []string{"argon2i", "argon2id"} {
		t.Run(kind, func(t *testing.T) {
			options := defaultLUKS2Options(patternBytes(512, 2))
			options.kdfType = kind
			options.argonPasses = 1
			options.argonMemoryKiB = 32
			options.argonLanes = 1
			image := buildLUKS2(t, options)
			unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
			if err != nil {
				t.Fatalf("Unlock: %v", err)
			}
			if unlocked.KDF != kind {
				t.Fatalf("kdf = %q, want %q", unlocked.KDF, kind)
			}
			if !bytes.Equal(unlocked.MasterKey(), options.masterKey) {
				t.Fatalf("master key = %x", unlocked.MasterKey())
			}
		})
	}
}

func TestUnlockLUKS2WrongPassphraseReturnsNoKey(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(512, 3))
	image := buildLUKS2(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), []byte("not the passphrase"))
	if unlocked != nil {
		t.Fatalf("wrong passphrase returned a volume: %+v", unlocked)
	}
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("error = %v, want ErrWrongPassphrase", err)
	}
}

func TestUnlockLUKS2RequiresTheDigestToConfirmTheKey(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(512, 4))
	image := buildLUKS2(t, options)
	// Corrupt the encrypted key-slot area: the recovered candidate no longer
	// matches the digest, so no key may be returned.
	image[options.areaOffset] ^= 0xff
	unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
	if unlocked != nil {
		t.Fatalf("a corrupt slot returned a volume: %+v", unlocked)
	}
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("error = %v, want ErrWrongPassphrase", err)
	}
}

// A description-only header may record a digest that names no key slot (no
// keyslots, salt or digest). That record cannot confirm anything, so unlocking
// must reach the passphrase check and refuse it there instead of failing while
// reading the metadata.
func TestUnlockLUKS2WithADigestThatNamesNoKeyslotReachesThePassphraseCheck(t *testing.T) {
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
	image = append(image, make([]byte, 16896-len(image))...)
	unlocked, err := Unlock(source.NewMemorySource(1, image), []byte("any passphrase"))
	if unlocked != nil {
		t.Fatalf("a volume without a verifying digest returned a key: %+v", unlocked)
	}
	if errors.Is(err, ErrMalformed) {
		t.Fatalf("the partial digest was treated as malformed metadata: %v", err)
	}
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("error = %v, want ErrWrongPassphrase", err)
	}
}

func TestUnlockLUKS2Refusals(t *testing.T) {
	plain := patternBytes(512, 5)
	t.Run("unsupported KDF", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.kdfKindOverride = "scrypt"
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedKDF) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported slot hash", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.kdfHash = "md5"
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedHash) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported slot type", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.slotType = "luks1"
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedFormat) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported area type", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.areaType = "checksum"
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedFormat) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported anti-forensic hash", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.afHash = "md5"
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedHash) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported area cipher", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.areaEnc = "serpent-xts-plain64"
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedCipher) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported segment cipher", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.segments[0].encryption = "serpent-xts-plain64"
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedCipher) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported sector size", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.segments[0].sectorSize = 1000
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedSectorSize) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported digest", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.digestType = "foo"
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedDigest) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("empty digest", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.digestSize = 0
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrGeometry) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("detached header", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.hdrOffset = 4096
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrDetachedHeader) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("truncated source", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image[:100]), options.passphrase)
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("key slot outside the source", func(t *testing.T) {
		options := defaultLUKS2Options(plain)
		options.areaOffset = 65536
		image := buildLUKS2(t, options)
		_, err := Unlock(source.NewMemorySource(1, image[:50000]), options.passphrase)
		if !errors.Is(err, ErrKeyslotOutside) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("no active key slot", func(t *testing.T) {
		document := `{"keyslots":{},"segments":{"0":{"type":"crypt","offset":32768,
          "size":"1024","iv_tweak":0,"encryption":"aes-xts-plain64","sector_size":512}}}`
		image := buildLUKS2Header(12288, document, 0)
		image = append(image, make([]byte, 34816-len(image))...)
		_, err := Unlock(source.NewMemorySource(1, image), []byte("x"))
		if !errors.Is(err, ErrNoActiveKeyslot) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestDeriveSlotKeyBounds(t *testing.T) {
	passphrase := []byte("passphrase")
	base := luks2Keyslot{
		index:   0,
		kind:    "luks2",
		keySize: 32,
		stripes: 2,
		afHash:  "sha256",
		area:    luks2Area{kind: "raw", keySize: 64, encryption: "aes-xts-plain64"},
	}
	t.Run("iterations", func(t *testing.T) {
		slot := base
		slot.kdf = luks2KDF{kind: "pbkdf2", hash: "sha256", iterations: uint32(MaxKDFIterations + 1), salt: []byte("somesalt")}
		_, err := deriveSlotKey(slot, passphrase)
		if !errors.Is(err, ErrIterations) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("argon2 passes", func(t *testing.T) {
		slot := base
		slot.kdf = luks2KDF{kind: "argon2id", passes: MaxArgon2Passes + 1, memoryKiB: 32, lanes: 1, salt: []byte("somesalt")}
		_, err := deriveSlotKey(slot, passphrase)
		if !errors.Is(err, ErrArgon2Passes) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("argon2 memory", func(t *testing.T) {
		slot := base
		slot.kdf = luks2KDF{kind: "argon2id", passes: 1, memoryKiB: MaxArgon2MemoryKiB + 1, lanes: 1, salt: []byte("somesalt")}
		_, err := deriveSlotKey(slot, passphrase)
		if !errors.Is(err, ErrArgon2Parameters) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestUnlockLUKS1XTS(t *testing.T) {
	options := defaultLUKS1Options(patternBytes(1024, 6))
	image := buildLUKS1(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if unlocked.Version != 1 || unlocked.Keyslot != 0 || unlocked.KDF != "pbkdf2" {
		t.Fatalf("identity = %+v", unlocked)
	}
	if unlocked.CipherMode() != "aes-xts-plain64" || unlocked.KeyBytes != 32 {
		t.Fatalf("cipher = %q, key = %d", unlocked.CipherMode(), unlocked.KeyBytes)
	}
	if unlocked.PayloadOffset != 40*512 || unlocked.PayloadLen != 1024 || unlocked.IVTweak != 0 {
		t.Fatalf("payload = %+v", unlocked)
	}
	if !bytes.Equal(unlocked.MasterKey(), options.masterKey) {
		t.Fatalf("master key = %x", unlocked.MasterKey())
	}
	if unlocked.Label() != "LUKS1 (key slot 0)" {
		t.Fatalf("label = %q", unlocked.Label())
	}
}

func TestUnlockLUKS1CBCEssiv(t *testing.T) {
	options := defaultLUKS1Options(patternBytes(1024, 7))
	options.mode = "cbc-essiv:sha256"
	image := buildLUKS1(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if unlocked.Mode != "cbc-essiv:sha256" || unlocked.CipherMode() != "aes-cbc-essiv:sha256" {
		t.Fatalf("mode = %q", unlocked.CipherMode())
	}
	if !bytes.Equal(unlocked.MasterKey(), options.masterKey) {
		t.Fatalf("master key = %x", unlocked.MasterKey())
	}
}

func TestUnlockLUKS1SHA1(t *testing.T) {
	options := defaultLUKS1Options(patternBytes(512, 8))
	options.hash = "sha1"
	image := buildLUKS1(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !bytes.Equal(unlocked.MasterKey(), options.masterKey) {
		t.Fatalf("master key = %x", unlocked.MasterKey())
	}
}

func TestUnlockLUKS1WrongPassphrase(t *testing.T) {
	options := defaultLUKS1Options(patternBytes(512, 9))
	image := buildLUKS1(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), []byte("wrong"))
	if unlocked != nil {
		t.Fatalf("wrong passphrase returned a volume: %+v", unlocked)
	}
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("error = %v", err)
	}
}

func TestUnlockLUKS1Refusals(t *testing.T) {
	plain := patternBytes(512, 10)
	t.Run("unsupported mode", func(t *testing.T) {
		options := defaultLUKS1Options(plain)
		image := buildLUKS1(t, options)
		copy(image[0x28:], "cbc-essiv:sha1")
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedCipher) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported cipher", func(t *testing.T) {
		options := defaultLUKS1Options(plain)
		image := buildLUKS1(t, options)
		copy(image[0x08:], "twofish")
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedCipher) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported hash", func(t *testing.T) {
		options := defaultLUKS1Options(plain)
		image := buildLUKS1(t, options)
		copy(image[0x48:], "md5")
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrUnsupportedHash) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unusable key size", func(t *testing.T) {
		options := defaultLUKS1Options(plain)
		image := buildLUKS1(t, options)
		putBE32(image, 0x6c, 20)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrKeyBytes) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("payload offset past the source", func(t *testing.T) {
		options := defaultLUKS1Options(plain)
		image := buildLUKS1(t, options)
		putBE32(image, 0x68, 1<<20)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrGeometry) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("truncated header", func(t *testing.T) {
		_, err := Unlock(source.NewMemorySource(1, make([]byte, 100)), []byte("x"))
		if !errors.Is(err, ErrNotLUKS) && !errors.Is(err, ErrTruncated) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("zero stripes", func(t *testing.T) {
		options := defaultLUKS1Options(plain)
		image := buildLUKS1(t, options)
		putBE32(image, 0xd0+44, 0)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrStripes) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("one stripe cannot hide a key", func(t *testing.T) {
		options := defaultLUKS1Options(plain)
		image := buildLUKS1(t, options)
		putBE32(image, 0xd0+44, 1)
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrAntiForensic) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("no master-key digest", func(t *testing.T) {
		options := defaultLUKS1Options(plain)
		image := buildLUKS1(t, options)
		zeroBytes(image[0x70:0x84])
		_, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
		if !errors.Is(err, ErrNoDigest) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestUnlockVersionAndMagicRefusals(t *testing.T) {
	if _, err := Unlock(source.NewMemorySource(1, []byte("not a LUKS volume")), []byte("x")); !errors.Is(err, ErrNotLUKS) {
		t.Fatalf("non-LUKS error = %v", err)
	}
	image := make([]byte, 1024)
	copy(image, "LUKS\xba\xbe")
	putBE16(image, 6, 3)
	if _, err := Unlock(source.NewMemorySource(1, image), []byte("x")); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("version error = %v", err)
	}
}
