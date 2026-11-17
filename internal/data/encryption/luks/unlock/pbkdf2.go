package unlock

// PBKDF2 (RFC 8018) over the four hashes cryptsetup accepts. LUKS1 uses
// SHA-1 or SHA-256 for both the key-slot derivation and the master-key digest;
// LUKS2 also accepts SHA-512 and RIPEMD-160 in a key slot's `pbkdf2` KDF and
// in a digest.
//
// The iteration count comes from on-disk metadata, so it is validated by the
// caller against MaxKDFIterations before this runs; zero is refused here.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strings"
)

// pbkdf2Hash describes one accepted PBKDF2 hash.
type pbkdf2Hash struct {
	name string
	size int
	new  func() hash.Hash
}

func pbkdf2HashByName(name string, luks1 bool) (pbkdf2Hash, bool) {
	switch strings.ToLower(name) {
	case "sha1":
		return pbkdf2Hash{name: "sha1", size: 20, new: sha1.New}, true
	case "sha256":
		return pbkdf2Hash{name: "sha256", size: 32, new: sha256.New}, true
	case "sha512":
		if luks1 {
			return pbkdf2Hash{}, false
		}
		return pbkdf2Hash{name: "sha512", size: 64, new: sha512.New}, true
	case "ripemd160":
		if luks1 {
			return pbkdf2Hash{}, false
		}
		return pbkdf2Hash{name: "ripemd160", size: 20, new: newRIPEMD160}, true
	default:
		return pbkdf2Hash{}, false
	}
}

// pbkdf2Key derives outLen bytes with HMAC over the hash.
func pbkdf2Key(hashFn func() hash.Hash, password, salt []byte, iterations uint32, outLen int) ([]byte, error) {
	if iterations == 0 {
		return nil, kdfErrorf("zero PBKDF2 iterations")
	}
	if outLen < 0 {
		return nil, kdfErrorf("negative PBKDF2 output length %d", outLen)
	}
	out := make([]byte, 0, outLen)
	block := uint32(1)
	for len(out) < outLen {
		mac := hmac.New(hashFn, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for round := uint32(1); round < iterations; round++ {
			mac = hmac.New(hashFn, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for index := range t {
				t[index] ^= u[index]
			}
		}
		take := outLen - len(out)
		if take > len(t) {
			take = len(t)
		}
		out = append(out, t[:take]...)
		block++
	}
	return out, nil
}
