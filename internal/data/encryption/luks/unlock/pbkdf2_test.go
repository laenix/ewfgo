package unlock

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"
)

func TestPBKDF2RFC6070SHA1Vectors(t *testing.T) {
	cases := []struct {
		iterations uint32
		want       string
	}{
		{1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{4096, "4b007901b765489abead49d926f721d065a429c1"},
	}
	for _, test := range cases {
		got, err := pbkdf2Key(sha1.New, []byte("password"), []byte("salt"), test.iterations, 20)
		if err != nil {
			t.Fatalf("%d iterations: %v", test.iterations, err)
		}
		if hexString(got) != test.want {
			t.Fatalf("%d iterations = %s, want %s", test.iterations, hexString(got), test.want)
		}
	}
}

func TestPBKDF2SHA256Vector(t *testing.T) {
	got, err := pbkdf2Key(sha256.New, []byte("password"), []byte("salt"), 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if hexString(got) != want {
		t.Fatalf("got %s, want %s", hexString(got), want)
	}
}

func TestPBKDF2SHA512Vector(t *testing.T) {
	// The long-published vector for password/salt/2/64.
	got, err := pbkdf2Key(sha512.New, []byte("password"), []byte("salt"), 2, 64)
	if err != nil {
		t.Fatal(err)
	}
	want := "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c" +
		"f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"
	if hexString(got) != want {
		t.Fatalf("got %s, want %s", hexString(got), want)
	}
}

func TestRIPEMD160PublishedVectors(t *testing.T) {
	cases := []struct{ message, want string }{
		{"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
		{"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
		{"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
	}
	for _, test := range cases {
		hasher := newRIPEMD160()
		hasher.Write([]byte(test.message))
		got := hasher.Sum(nil)
		if hexString(got) != test.want {
			t.Fatalf("RIPEMD160(%q) = %s, want %s", test.message, hexString(got), test.want)
		}
	}
}

func TestPBKDF2RIPEMD160Vector(t *testing.T) {
	got, err := pbkdf2Key(newRIPEMD160, []byte("password"), []byte("salt"), 2, 64)
	if err != nil {
		t.Fatal(err)
	}
	want := "768dcc27b7bfdef794a1ff9d935090fcf598555e66913180b9ce363c615e9ed9" +
		"53b95fd07169be535e38afbea29c030e06d14f40745b1513b7ccdf0e76229e50"
	if hexString(got) != want {
		t.Fatalf("got %s, want %s", hexString(got), want)
	}
}

func TestPBKDF2RefusesZeroIterations(t *testing.T) {
	_, err := pbkdf2Key(sha256.New, []byte("password"), []byte("salt"), 0, 32)
	if !errors.Is(err, ErrKDF) {
		t.Fatalf("zero iterations error = %v", err)
	}
}

func TestPBKDF2HashSelection(t *testing.T) {
	cases := []struct {
		name  string
		luks1 bool
		ok    bool
		size  int
	}{
		{"sha1", false, true, 20},
		{"SHA256", false, true, 32},
		{"sha512", false, true, 64},
		{"RIPEMD160", false, true, 20},
		{"sha512", true, false, 0},
		{"ripemd160", true, false, 0},
		{"md5", false, false, 0},
		{"sha384", false, false, 0},
	}
	for _, test := range cases {
		hash, ok := pbkdf2HashByName(test.name, test.luks1)
		if ok != test.ok {
			t.Fatalf("%q luks1=%v: accepted=%v, want %v", test.name, test.luks1, ok, test.ok)
		}
		if ok && hash.size != test.size {
			t.Fatalf("%q size = %d, want %d", test.name, hash.size, test.size)
		}
	}
}
