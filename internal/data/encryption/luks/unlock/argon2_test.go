package unlock

import (
	"errors"
	"testing"
)

func rfc9106Params(variant argon2Variant) argon2Params {
	return argon2Params{variant: variant, passes: 3, memoryKiB: 32, lanes: 4, tagBytes: 32}
}

func rfc9106Inputs() (password, salt, secret, ad []byte) {
	return bytesOf(0x01, 32), bytesOf(0x02, 16), bytesOf(0x03, 8), bytesOf(0x04, 12)
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for index := range out {
		out[index] = value
	}
	return out
}

func TestArgon2RFC9106InitialHash(t *testing.T) {
	password, salt, secret, ad := rfc9106Inputs()
	h0 := argon2InitialHash(rfc9106Params(argon2D), password, salt, secret, ad)
	want := "b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757" +
		"082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109"
	if hexString(h0) != want {
		t.Fatalf("H0 = %s, want %s", hexString(h0), want)
	}
}

func TestArgon2RFC9106Tags(t *testing.T) {
	password, salt, secret, ad := rfc9106Inputs()
	cases := []struct {
		variant argon2Variant
		want    string
	}{
		{argon2D, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"},
		{argon2I, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"},
		{argon2ID, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"},
	}
	for _, test := range cases {
		tag, err := argon2Hash(rfc9106Params(test.variant), password, salt, secret, ad)
		if err != nil {
			t.Fatalf("%s: %v", test.variant.name(), err)
		}
		if hexString(tag) != test.want {
			t.Fatalf("%s tag = %s, want %s", test.variant.name(), hexString(tag), test.want)
		}
	}
}

func TestArgon2TagLengthIsTheOutputLength(t *testing.T) {
	for _, length := range []int{16, 32, 64, 100} {
		params := rfc9106Params(argon2ID)
		params.tagBytes = length
		tag, err := argon2Hash(params, []byte("password"), []byte("somesalt"), nil, nil)
		if err != nil {
			t.Fatalf("tag length %d: %v", length, err)
		}
		if len(tag) != length {
			t.Fatalf("tag length %d produced %d bytes", length, len(tag))
		}
	}
}

func TestArgon2LongTagIsNotATruncation(t *testing.T) {
	shortParams := rfc9106Params(argon2ID)
	shortParams.tagBytes = 32
	longParams := shortParams
	longParams.tagBytes = 100
	short, _ := argon2Hash(shortParams, []byte("password"), []byte("somesalt"), nil, nil)
	long, _ := argon2Hash(longParams, []byte("password"), []byte("somesalt"), nil, nil)
	if hexString(short) == hexString(long[:32]) {
		t.Fatal("a 100-byte tag must not begin with the 32-byte tag")
	}
}

func TestArgon2SecretAndAssociatedDataChangeTheTag(t *testing.T) {
	params := rfc9106Params(argon2ID)
	password, salt, _, _ := rfc9106Inputs()
	plain, _ := argon2Hash(params, password, salt, nil, nil)
	withSecret, _ := argon2Hash(params, password, salt, []byte("key"), nil)
	withAD, _ := argon2Hash(params, password, salt, nil, []byte("ad"))
	if hexString(plain) == hexString(withSecret) || hexString(plain) == hexString(withAD) ||
		hexString(withSecret) == hexString(withAD) {
		t.Fatal("secret and associated data must change the tag")
	}
}

// The >64-byte branch of H' chains BLAKE2b; these values were computed with
// Python's hashlib.blake2b from the RFC 9106 section 3.3 definition, so the
// extension is pinned to an implementation that is not ours.
func TestArgon2VariableHashLongerThanOneBlock(t *testing.T) {
	cases := []struct {
		outlen int
		want   string
	}{
		{64, "0e7118e29d495ab28a5a9245b1d0f679e503b91a65f77527d0d24acdd035fde1" +
			"106b9ba967b7f77f8555f1006336c59b9fb0df67cb070614e7e825d8b86f5a49"},
		{65, "09a645c1744ef298cb054ed632aad71d9b8a5ef09c5533305fc5e759a9e6a332" +
			"bd35390f81c0b2c3269901ad3e102481519439cf2638d102cd6a1f26ea3d336d4b"},
		{100, "c4f582cf240a8f0bcc8d882346efc9b2081dad5d1b83526c48af77ce2102382d" +
			"144fffb5e9327ba564207284915aef7dd26521eae4c5f1afb9da79191009f37c4fba4" +
			"532b6b0e07623a043c047520a88c8c097416042d2e2fa2385346b8d11adfbf83231"},
	}
	for _, test := range cases {
		got, ok := argon2VariableHash([]byte("input"), test.outlen)
		if !ok {
			t.Fatalf("length %d refused", test.outlen)
		}
		if hexString(got) != test.want {
			t.Fatalf("H'(%d) = %s, want %s", test.outlen, hexString(got), test.want)
		}
	}
}

func TestArgon2RefusesUnboundedParametersBeforeAllocating(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*argon2Params)
	}{
		{"short tag", func(p *argon2Params) { p.tagBytes = 2 }},
		{"long tag", func(p *argon2Params) { p.tagBytes = argon2MaxTagBytes + 1 }},
		{"no lanes", func(p *argon2Params) { p.lanes = 0 }},
		{"too many lanes", func(p *argon2Params) { p.lanes = argon2MaxLanes + 1 }},
		{"no passes", func(p *argon2Params) { p.passes = 0 }},
		{"too much memory", func(p *argon2Params) { p.memoryKiB = argon2MaxMemoryKiB + 1 }},
		{"too little memory", func(p *argon2Params) { p.memoryKiB = 8 }},
	}
	for _, test := range cases {
		params := rfc9106Params(argon2ID)
		test.mutate(&params)
		err := params.validate()
		if !errors.Is(err, ErrArgon2Parameters) {
			t.Fatalf("%s: validate = %v, want ErrArgon2Parameters", test.name, err)
		}
	}
}

func TestArgon2RefusesAShortSalt(t *testing.T) {
	_, err := argon2Hash(rfc9106Params(argon2ID), []byte("password"), []byte("short"), nil, nil)
	if !errors.Is(err, ErrArgon2Parameters) {
		t.Fatalf("short salt error = %v", err)
	}
}

func TestArgon2RoundsMemoryDownToWholeLanes(t *testing.T) {
	params := rfc9106Params(argon2ID)
	params.memoryKiB = 46
	if got := params.argon2Blocks(); got != 32 {
		t.Fatalf("memory blocks = %d, want 32", got)
	}
	tag, err := argon2Hash(params, []byte("password"), []byte("somesalt"), nil, nil)
	if err != nil || len(tag) != 32 {
		t.Fatalf("rounded derivation = %d bytes, %v", len(tag), err)
	}
}
