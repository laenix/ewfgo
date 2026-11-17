package xz

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"strconv"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The fixtures below were produced once by the reference XZ encoder
// (Python's lzma module, which wraps liblzma; the manual fixtures were built
// from raw LZMA2 data and validated with the same decoder) and are embedded
// so the tests stay hermetic: no external tool or network at test time.

// A valid stream whose LZMA2 chunk stream is only the end marker. Decodes to
// the empty payload.
const xzEmptyHex = "fd377a585a0000016922de36000000001cdf44219042990d010000000001595a"

// One LZMA-compressed block with no stored sizes, check CRC32. Decodes to
// testText.
const xzTextHex = "fd377a585a0000016922de360200210116000000742fe5a3e000c3006c5d0026984a420bb4ebd87ff30eabfebdfc7d3582b4165f1846d1d9e62227d7b817333cae3167f26657aebcc3cacff80686f850f2b477e52f8f3bde04560cf4bc4dbe242a4d31c394866ea1c122574a580de2eeb71935c1fd34c7697d8ad51c07e6d8db3d92e6be0fb53c447bc8a00074cc31b700018401c4010000c5b8f9833e300d8b020000000001595a"

// The same payload with Check ID None.
const xzTextNoneHex = "fd377a585a000000ff12d9410200210116000000742fe5a3e000c3006c5d0026984a420bb4ebd87ff30eabfebdfc7d3582b4165f1846d1d9e62227d7b817333cae3167f26657aebcc3cacff80686f850f2b477e52f8f3bde04560cf4bc4dbe242a4d31c394866ea1c122574a580de2eeb71935c1fd34c7697d8ad51c07e6d8db3d92e6be0fb53c447bc8a00000018001c4010000d3fa6818a8000afc020000000000595a"

// Two streams back to back. Decodes to "first line\n" + secondLine.
const xzTwoStreamsHex = "fd377a585a0000016922de360200210116000000742fe5a301000a6669727374206c696e650a000010fcefbd00011f0b3d620e7a9042990d010000000001595afd377a585a0000016922de360200210116000000742fe5a30100257365636f6e64206c696e652c206120626974206c6f6e67657220746f20636f6d70726573730a000000f3303b6d00013a26afee22d79042990d010000000001595a"

// The same two streams separated by four padding bytes, with eight trailing
// padding bytes.
const xzPaddingHex = "fd377a585a0000016922de360200210116000000742fe5a301000a6669727374206c696e650a000010fcefbd00011f0b3d620e7a9042990d010000000001595a00000000fd377a585a0000016922de360200210116000000742fe5a30100257365636f6e64206c696e652c206120626974206c6f6e67657220746f20636f6d70726573730a000000f3303b6d00013a26afee22d79042990d010000000001595a0000000000000000"

// liblzma-compressed 700-byte pattern.
const xzStoredHex = "fd377a585a0000016922de36020021010c0000008f98419ce002bb00f85d00149c9360429f260b3e08c28fcaa1d032fb86f2b81f376974377097b25e1effdd6646dd3a1a4e128b952d85125313b1281469ff08be4cb4319902f7906ac3a43a311e5a08c8b13022a280ec7ddbbe6b37aff47bf8b9f9da29d0051b9ef3e89455a1a71bca3d9b1275f3f69a0a2a40909b590a4eb19e2ecc6887d0e73fbbbf0aa97cf0b87511830e863c057021d1e6b2e703d4372ae8a1966a860a920c588b35f65a663f97466ac4e0842561021058fd94822c9db7cfd6276fd7596288f28629c428a3d4020920df33b35a0e77f09acbc5e388788819f3c53aca8ca6aad6403de6d7ed4989b82ffb587d7be56ddf82c3cfc3f390896104b80000b597efb400019002bc05000037a29cf53e300d8b020000000001595a"

// A high-entropy payload encoded as LZMA chunks by liblzma.
const xzCompressedHex = "fd377a585a0000016922de360200210116000000742fe5a3e00abd00495d003a1a08ce76c7e5e9d60734c3d10ebfce55e1aabde0e48f9801dd8de507549e65255f273a6a7eb4d34900b672dab374e50af69ad9071d01ce5b58124faba0cafc3c1c4faaed8e67e2d400000000f326b037000161be15000000fa19cdc83e300d8b020000000001595a"

// One block carrying 1,028,000 decoded bytes.
const xzLargeSingleBlockHex = "fd377a585a0000016922de36020021010c0000008f98419cefaf9f00f15d00180c42926a67bc0ed1332ce4cc4229c09c483d399e4c53d532ac2b23e7b449f3d494996a727cc18504c94c69e724e8e5da6b0f7efce8c0ed8227e42b12e7f3c601e05b74064cbf95423d78eeead5fa5d532ab4daf8602a30df67a089c953c978dee015ca203f02c9a60ad651e6f25004f55b7943aa6675ceb1e72623a8f8068bd9f57fd60d1b3f7d77ab8314216ed1d57af33e14536276ac59e4e55b0508f9c7daadfcfb522b74cd1e5b2042f9dd533df82964093b80cb2a6cdfb53bf0c4bd2e5faa0f3e4b664290130eff1093f8717859f80bcdff9528460fa9fc7cdefb9a302e56c08f85f38381c065c41bdb1c0440000000000083aa0db400018902a0df3e00d8b2510a3e300d8b020000000001595a"

// Two blocks in one stream, each carrying 514,000 decoded bytes.
const xzTwoBlocksHex = "fd377a585a0000016922de3603c0b001d0af1f2101100000e1002a29e7d7cf00a85d00180c42926a67bc0ed1332ce4cc4229c09c483d399e4c53d532ac2b23e7b449f3d494996a727cc18504c94c69e724e8e5da6b0f7efce8c0ed8227e42b12e7f3c601e05b74064cbf95423d78eeead5fa5d532ab4daf8602a30df67a089c953c978dee015ca203f02c9a60ad651e6f25004f55b7943aa6675ceb1e72623a8f8068bd9f57fd60d1b3f7d77ab8314216ed1d57af33e14536276ac59e4e55b0508f9c7daadfc5c21de8100000d3f27dc03c0b001d0af1f2101100000e1002a29e7d7cf00a85d00180c42926a67bc0ed1332ce4cc4229c09c483d399e4c53d532ac2b23e7b449f3d494996a727cc18504c94c69e724e8e5da6b0f7efce8c0ed8227e42b12e7f3c601e05b74064cbf95423d78eeead5fa5d532ab4daf8602a30df67a089c953c978dee015ca203f02c9a60ad651e6f25004f55b7943aa6675ceb1e72623a8f8068bd9f57fd60d1b3f7d77ab8314216ed1d57af33e14536276ac59e4e55b0508f9c7daadfc5c21de8100000d3f27dc0002c401d0af1fc401d0af1f7e11df8d9be35140030000000001595a"

// One block whose LZMA2 stream has two LZMA chunks: the second continues the
// first chunk's state (control 0x80, no reset). Decodes to multiChunkPayload.
const xzMultiChunkHex = "fd377a585a0000016922de360200210116000000742fe5a3ffff4701a25d003a1a08ce76c7e5e9d60734c3d10ebfce55e1aabde0e48f9801dd8de507549e65255f273a6a7eb4d34900b672dab374e50af69ad9071d01ce5b58124faba0cafc3c1c4faaedcc8a40b8059657bc8fa523f9d2dcaac0601a92548678c46f172ab1fe1743fed96b658ed1c55ff12d89582aa7d50f99dc3b3f7d9f8dd8c1e2711705118dd8ed18436317e8b7275273b92aa51e8aa89aa85e249e69d1e0c6dd9dfdd6257859f80bcdff9528460fa9fc7cdefb9a302e56c08f85f38381c065c42553f8f591363105a5b0ee6fc1704d470cd19111aaad601dbaceb127185c5986e9665258bee976ac59e4e55b0508f9c7daadfcfb522b74cd1e5b2042f9dd533df82964093b80cb2a6cdfb53bf0c4bd2e5faa0f3e4b664290130eff1093f8717859f80bcdff9528460fa9fc7cdefb9a302e56c08f85f38381c065c42553f8f591363105a5b0ee6fc1704d470cd19111aaad601dbaceb127185c5986e9665258bee976ac59e4e55b0508f9c7daadfcfb522b74cd1e5b2042f9dd533df82964093b80cb2a6cdfb53bf0c4bd2e5faa0f3e4b664290130eff1093f8717859f80bcdff950b90806389f6e7006100ec7353a7fdbeae7c311a9fb78d316e709ea7235fec28cb85d195988a7e2a91f22775f719c006984d98fdd8afd5900fc42553f8f591363105a5b0ee6fc1704d470cd19111aaad601dbaceb127185c5986e9665258bee976ac59e4e55a9176733b00000000006975eced0001a104b0eca701b0cd5ecf3e300d8b020000000001595a"

// Check ID SHA-256; recognised and refused.
const xzSHA256Hex = "fd377a585a00000ae1fb0ca10200210116000000742fe5a3e000c3006c5d0026984a420bb4ebd87ff30eabfebdfc7d3582b4165f1846d1d9e62227d7b817333cae3167f26657aebcc3cacff80686f850f2b477e52f8f3bde04560cf4bc4dbe242a4d31c394866ea1c122574a580de2eeb71935c1fd34c7697d8ad51c07e6d8db3d92e6be0fb53c447bc8a0000c55be108a4501fa5571adf8c246c9498b6a19b56c5b320a432f728a2a55e49b0001a001c4010000e5ffc41fb6e9df1c02000000000a595a"

// Check ID CRC64; recognised and refused.
const xzCRC64Hex = "fd377a585a000004e6d6b4460200210116000000742fe5a3e000c3006c5d0026984a420bb4ebd87ff30eabfebdfc7d3582b4165f1846d1d9e62227d7b817333cae3167f26657aebcc3cacff80686f850f2b477e52f8f3bde04560cf4bc4dbe242a4d31c394866ea1c122574a580de2eeb71935c1fd34c7697d8ad51c07e6d8db3d92e6be0fb53c447bc8a000e9f80c842afc5e9c00018801c4010000be783bf4b1c467fb020000000004595a"

// Delta + LZMA2 filter chain; refused as unsupported.
const xzDeltaHex = "fd377a585a0000016922de3602010301002101167920c4eee000c3007c5d002684fe2aa5e848b6ff5306e157f6d437dba4e5fb4ed0d62641e0f524c04834fb627a830586cb324d5ce3cd0dbd162a72a71ad1b1e2a8f145e5f14e687868d43e9bc9680b5001a7383e0cf89d6cdb67e1601c823196235732ce4f801a965e385ef89bf76c3346767dcda922181da48ff9f273208d522c17271e62cb660074cc31b700019401c40100005eba2f803e300d8b020000000001595a"

// x86 BCJ + LZMA2 filter chain; refused as unsupported.
const xzBCJHex = "fd377a585a0000016922de3602010400210116000d86351fe0012b00f75d0000020f570268c678ced80f90e6ebb6dd1f7062b0212714f9b1958a5860217a2cace77798df4586daac6934690d386455e2b71816aa441599bea2908b09d61fc947ffefde9ac68dbf33d9b5d46aaf16edf483bc6974d123e6c7841e129ba67590569089721a587f5a3e80064c56653f78ebadd7c6553b1f67e3a8378a1999f24ce6a5cb0071895bcf16238192f1f707bf9beedcfa16130e51d01069883edee4bdc3a6e095832b4ba89575987a1b8a027478a6a1fc6a60f0a5ad2ac855c4cf2f060f621b9d85b9151cc89b941966d406208626a3ad7c6884022f7b8f2b57723256b3d8880f4d7f03563dc3d59837c3eae0f39fab3a6400000000fbb100e000018f02ac02000063534a523e300d8b020000000001595a"

// A manually built block whose LZMA2 stream is one stored (uncompressed)
// chunk. Decodes to manualStoredPayload.
const xzManualStoredHex = "fd377a585a0000016922de3603c0b002ac02210128000000480089f301012b0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b50759abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21466b90b5daff24496e93b8dd02274c7196bbe0052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d4200765eec320001c402ac020000cca9d5373e300d8b020000000001595a"

// A manually built block with two stored chunks, the second continuing the
// dictionary. Decodes to manualTwoStoredPayload.
const xzManualTwoStoredHex = "fd377a585a0000016922de3602c0332c210128005ffcd42901001368656c6c6f20726177206368756e6b206f6e6520020017616e6420746865207365636f6e6420726177206368756e6b0000889768ab0001432c0ec50ac99042990d010000000001595a"

// A high-entropy payload that liblzma stores as uncompressed LZMA2 chunks.
const xzRandomStoredHex = "fd377a585a0000016922de36020021010c0000008f98419c0101ffdcf26a21079d636152462f837e06d078282792c3ac791e062081242e561f2bb73cddb091aba13be8720fe946560151e42b8456ac5b9b646752bc4ec92a58998f7c447014cfe1b9d87a412af99c2ae9487b47eb15e219ba60d36eaaf177783a7e391a9e726a8bdd6b38df3f5db637876115e84fe4c90f8837196c02be06bc8e6d98aa9334cbf240b3d16d7cf837ec6c5a3e29cdd3d46ccd80fc0181ef61a31cdd7ccdf49c38775fa84b1c888bb126dc0606e7e9e2db2e0c8377213539525ecf24501a347575fee4ec9d04e749fd453fb1f75a18d7ab2facaf942223af122713925fd21906bf70dc2f456833b18eda2b30d5e08991fb716722da7a19df1cd03de7e1438066b4c80fc74ee5639cf1e16c2fddc0c2c340c22104c9e9a67f0a54ee768e662adf21f22452e86efcae38a9385b7e1a4984faf6adffd6ca3dc5e337bc46af4c0ebc2d72d415756db823b75112ee17fd20a71b3e39239de00153f490c1947e05686525abd2e4a388e3dc43870e9371ad8276e2160ad92675334ef5424434ad6f6f4f80023d456fa71f9478acc0d272055603a840453c5e70720d507c5f7f57dc232de4ab16e6a2ac4490d24d7306d8ed05479613d0bffa601e2d45ed862091af2917dd1f2c458749a301b1d01586e77bfa7a1ad4e0b789093c387739de8f74e9d747654da51086328ad41ae9fc3e75f4e83127b65b375d56f7019642302f00764eae1c0001940480040000af38725a3e300d8b020000000001595a"

// The decoded payload of xzRandomStoredHex.
const xzRandomStoredPayloadHex = "dcf26a21079d636152462f837e06d078282792c3ac791e062081242e561f2bb73cddb091aba13be8720fe946560151e42b8456ac5b9b646752bc4ec92a58998f7c447014cfe1b9d87a412af99c2ae9487b47eb15e219ba60d36eaaf177783a7e391a9e726a8bdd6b38df3f5db637876115e84fe4c90f8837196c02be06bc8e6d98aa9334cbf240b3d16d7cf837ec6c5a3e29cdd3d46ccd80fc0181ef61a31cdd7ccdf49c38775fa84b1c888bb126dc0606e7e9e2db2e0c8377213539525ecf24501a347575fee4ec9d04e749fd453fb1f75a18d7ab2facaf942223af122713925fd21906bf70dc2f456833b18eda2b30d5e08991fb716722da7a19df1cd03de7e1438066b4c80fc74ee5639cf1e16c2fddc0c2c340c22104c9e9a67f0a54ee768e662adf21f22452e86efcae38a9385b7e1a4984faf6adffd6ca3dc5e337bc46af4c0ebc2d72d415756db823b75112ee17fd20a71b3e39239de00153f490c1947e05686525abd2e4a388e3dc43870e9371ad8276e2160ad92675334ef5424434ad6f6f4f80023d456fa71f9478acc0d272055603a840453c5e70720d507c5f7f57dc232de4ab16e6a2ac4490d24d7306d8ed05479613d0bffa601e2d45ed862091af2917dd1f2c458749a301b1d01586e77bfa7a1ad4e0b789093c387739de8f74e9d747654da51086328ad41ae9fc3e75f4e83127b65b375d56f7019642302f"

// The same payload as xzRandomStoredHex, but with neither size field in the
// block header: the compressed length must be found from the LZMA2 end mark.
const xzUnknownSizesHex = "fd377a585a0000016922de360200210128000000e6a011b30101ffdcf26a21079d636152462f837e06d078282792c3ac791e062081242e561f2bb73cddb091aba13be8720fe946560151e42b8456ac5b9b646752bc4ec92a58998f7c447014cfe1b9d87a412af99c2ae9487b47eb15e219ba60d36eaaf177783a7e391a9e726a8bdd6b38df3f5db637876115e84fe4c90f8837196c02be06bc8e6d98aa9334cbf240b3d16d7cf837ec6c5a3e29cdd3d46ccd80fc0181ef61a31cdd7ccdf49c38775fa84b1c888bb126dc0606e7e9e2db2e0c8377213539525ecf24501a347575fee4ec9d04e749fd453fb1f75a18d7ab2facaf942223af122713925fd21906bf70dc2f456833b18eda2b30d5e08991fb716722da7a19df1cd03de7e1438066b4c80fc74ee5639cf1e16c2fddc0c2c340c22104c9e9a67f0a54ee768e662adf21f22452e86efcae38a9385b7e1a4984faf6adffd6ca3dc5e337bc46af4c0ebc2d72d415756db823b75112ee17fd20a71b3e39239de00153f490c1947e05686525abd2e4a388e3dc43870e9371ad8276e2160ad92675334ef5424434ad6f6f4f80023d456fa71f9478acc0d272055603a840453c5e70720d507c5f7f57dc232de4ab16e6a2ac4490d24d7306d8ed05479613d0bffa601e2d45ed862091af2917dd1f2c458749a301b1d01586e77bfa7a1ad4e0b789093c387739de8f74e9d747654da51086328ad41ae9fc3e75f4e83127b65b375d56f7019642302f00764eae1c0001940480040000af38725a3e300d8b020000000001595a"

// A manually built block with known sizes and two bytes of block padding,
// ending in a compressed LZMA chunk. Decodes to knownSizedPayload.
const xzKnownPaddingHex = "fd377a585a0000016922de3602c07a85012101104d3c3abde0008400725d00359b8a430b4c3416a9ae82b3c6a4461cd4682e3f2315965c5c7f014bd9756cf77240996f0e60b916b60baf8d3142a97873b996b905cde73dbeaa5ccbc185a88df6adb4c4b668011b79bf539ebc68854874d55be3f45489fdfe6a4e4295c789095c9c03f0e65c013f4c893082d9f0c5bda000000000d32838bc00018a0185010000ede65b9a3e300d8b020000000001595a"

// The same block with a known compressed size but no uncompressed size.
const xzKnownNoUncompressedHex = "fd377a585a0000016922de3602407a21011000006b418e91e0008400725d00359b8a430b4c3416a9ae82b3c6a4461cd4682e3f2315965c5c7f014bd9756cf77240996f0e60b916b60baf8d3142a97873b996b905cde73dbeaa5ccbc185a88df6adb4c4b668011b79bf539ebc68854874d55be3f45489fdfe6a4e4295c789095c9c03f0e65c013f4c893082d9f0c5bda000000000d32838bc00018a0185010000ede65b9a3e300d8b020000000001595a"

const xzKnownPayloadHex = "6b6e6f776e2d73697a6520626c6f636b3a20626c6f636b2070616464696e67206d757374206265207a65726f2062797465733b2074686973207061796c6f6164206973206c6f6e6720656e6f75676820746f206d616b652074686520656e74726f707920636f6465722063686f6f7365206120636f6d70726573736564206368756e6b2e0a"

const (
	testText = "Mar  1 10:00:00 host sshd[1]: Accepted password for alice from 198.51.100.7\n" +
		"Mar  1 10:00:01 host sshd[1]: session opened for user alice\n" +
		"Mar  1 10:00:02 host sshd[1]: session closed for user alice\n"

	firstLine  = "first line\n"
	secondLine = "second line, a bit longer to compress\n"

	manualTwoStoredPayload = "hello raw chunk one and the second raw chunk"
)

// bigPattern is the payload used by the 1 MiB fixtures.
func bigPattern() []byte {
	unit := append(bytes.Repeat([]byte("0123456789abcdef"), 16), '\n')
	return bytes.Repeat(unit, 4000)
}

// multiChunkPayload is the 2.75 MB payload of the two-chunk LZMA2 fixture.
func multiChunkPayload() []byte {
	return bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog 0123456789\n"), 50000)
}

func pattern(n, mul, add int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*mul + add) % 256)
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture hex: %v", err)
	}
	return b
}

func openBytes(t *testing.T, stored []byte, limits Limits) (*Source, error) {
	t.Helper()
	return Open(2, source.NewMemorySourceWithImage(1, 9, stored), limits)
}

func mustOpen(t *testing.T, stored []byte) *Source {
	t.Helper()
	src, err := openBytes(t, stored, DefaultLimits())
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return src
}

func assertBytes(t *testing.T, src *Source, want []byte) {
	t.Helper()
	if got := src.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("decoded %d bytes, want %d; first difference at %d",
			len(got), len(want), firstDiff(got, want))
	}
	if src.Len() != uint64(len(want)) {
		t.Fatalf("Len = %d, want %d", src.Len(), len(want))
	}
	buf := make([]byte, src.Len())
	n, err := src.ReadAt(0, buf)
	if err != nil {
		t.Fatalf("ReadAt error = %v", err)
	}
	if n != len(buf) || !bytes.Equal(buf, want) {
		t.Fatalf("ReadAt delivered %d bytes, want %d", n, len(want))
	}
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func TestMatchesSignature(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want bool
	}{
		{"magic", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, true},
		{"magic plus data", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00}, true},
		{"short", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A}, false},
		{"gzip", []byte{0x1F, 0x8B}, false},
		{"lz4", []byte{0x04, 0x22, 0x4D, 0x18}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		if got := MatchesSignature(tc.head); got != tc.want {
			t.Errorf("MatchesSignature(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestOpenDecodesFixtures(t *testing.T) {
	big := bigPattern()
	cases := []struct {
		name        string
		hexData     string
		want        []byte
		wantStreams uint64
		wantPadding uint64
	}{
		{"empty payload", xzEmptyHex, nil, 1, 0},
		{"crc32 one block", xzTextHex, []byte(testText), 1, 0},
		{"check none", xzTextNoneHex, []byte(testText), 1, 0},
		{"concatenated streams", xzTwoStreamsHex, []byte(firstLine + secondLine), 2, 0},
		{"stream padding", xzPaddingHex, []byte(firstLine + secondLine), 2, 12},
		{"liblzma stored", xzStoredHex, pattern(700, 73, 41), 1, 0},
		{"liblzma compressed", xzCompressedHex,
			bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog 0123456789\n"), 50), 1, 0},
		{"large single block", xzLargeSingleBlockHex, big, 1, 0},
		{"two blocks", xzTwoBlocksHex, big, 1, 0},
		{"multi-chunk LZMA2", xzMultiChunkHex, multiChunkPayload(), 1, 0},
		{"manual stored chunk", xzManualStoredHex, pattern(300, 37, 11), 1, 0},
		{"manual two stored chunks", xzManualTwoStoredHex, []byte(manualTwoStoredPayload), 1, 0},
		{"random stored chunks", xzRandomStoredHex, mustHex(t, xzRandomStoredPayloadHex), 1, 0},
		{"unknown sizes", xzUnknownSizesHex, mustHex(t, xzRandomStoredPayloadHex), 1, 0},
		{"known sizes with padding", xzKnownPaddingHex, mustHex(t, xzKnownPayloadHex), 1, 0},
		{"known compressed no uncompressed", xzKnownNoUncompressedHex, mustHex(t, xzKnownPayloadHex), 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored := mustHex(t, tc.hexData)
			src := mustOpen(t, stored)
			assertBytes(t, src, tc.want)
			if src.CompressedLen() != uint64(len(stored)) {
				t.Fatalf("CompressedLen = %d, want %d", src.CompressedLen(), len(stored))
			}
			meta := src.Meta()
			if meta.CompressedLen != uint64(len(stored)) ||
				meta.DecompressedLen != uint64(len(tc.want)) ||
				meta.Streams != tc.wantStreams ||
				meta.PaddingBytes != tc.wantPadding {
				t.Fatalf("meta = %+v, want streams %d padding %d", meta, tc.wantStreams, tc.wantPadding)
			}
			if tc.wantStreams > 1 && tc.wantPadding > 0 && meta.PaddingBytes != tc.wantPadding {
				t.Fatalf("padding = %d, want %d", meta.PaddingBytes, tc.wantPadding)
			}
			if src.IsEmpty() != (len(tc.want) == 0) {
				t.Fatalf("IsEmpty = %v, want %v", src.IsEmpty(), len(tc.want) == 0)
			}
			if stats := src.Stats(); stats.DecompressedBytes != uint64(len(tc.want)) {
				t.Fatalf("stats.DecompressedBytes = %d, want %d", stats.DecompressedBytes, len(tc.want))
			}
		})
	}
}

func TestOpenLeadingStreamPadding(t *testing.T) {
	stored := append([]byte{0, 0, 0, 0}, mustHex(t, xzTextHex)...)
	src := mustOpen(t, stored)
	assertBytes(t, src, []byte(testText))
	if src.Meta().PaddingBytes != 4 || src.Meta().Streams != 1 {
		t.Fatalf("meta = %+v", src.Meta())
	}
}

func TestOpenErrors(t *testing.T) {
	text := mustHex(t, xzTextHex)
	badPadding := append([]byte{}, mustHex(t, xzTwoStreamsHex)...)
	secondMagic := bytes.Index(badPadding[12:], []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}) + 12
	badPadding = append(append(append([]byte{}, badPadding[:secondMagic]...), 0, 0), badPadding[secondMagic:]...)

	headerCRC := append([]byte{}, text...)
	headerCRC[8] ^= 0x01
	indexCRC := append([]byte{}, text...)
	indexCRC[len(indexCRC)-16] ^= 0x01
	footerCRC := append([]byte{}, text...)
	footerCRC[len(footerCRC)-12] ^= 0x01
	blockCRC := append([]byte{}, text...)
	blockCRC[len(blockCRC)-28] ^= 0x01 // the Check field before the index
	blockPadding := mustHex(t, xzKnownPaddingHex)
	blockPadding[146] = 0xFF // first of the two block-padding bytes
	indexPadding := append([]byte{}, text...)
	indexPadding[len(indexPadding)-18] = 0xFF // index padding byte

	reservedHeader := append([]byte{}, text...)
	reservedHeader[6] = 0x01
	unknownCheck := append([]byte{}, text...)
	unknownCheck[7] = 0x02
	reservedBlock := append([]byte{}, text...)
	reservedBlock[13] |= 0x04
	binary.LittleEndian.PutUint32(reservedBlock[20:24], crc32.ChecksumIEEE(reservedBlock[12:20]))
	unsupportedFilter := append([]byte{}, text...)
	unsupportedFilter[14] = 0x03 // Delta, a valid but unsupported filter ID
	binary.LittleEndian.PutUint32(unsupportedFilter[20:24],
		crc32.ChecksumIEEE(unsupportedFilter[12:20]))

	cases := []struct {
		name   string
		data   []byte
		limits Limits
		want   error
		substr string
	}{
		{"not xz", []byte("this is definitely not an xz stream at all"), DefaultLimits(), source.ErrCorrupt, "not an xz stream"},
		{"zero length", nil, DefaultLimits(), source.ErrCorrupt, "too short"},
		{"too short", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, DefaultLimits(), source.ErrCorrupt, "too short"},
		{"padding only", make([]byte, 64), DefaultLimits(), source.ErrCorrupt, "no xz stream"},
		{"bad stream padding", badPadding, DefaultLimits(), source.ErrCorrupt, "padding"},
		{"header CRC", headerCRC, DefaultLimits(), source.ErrCorrupt, "header CRC32"},
		{"index CRC", indexCRC, DefaultLimits(), source.ErrCorrupt, "index CRC32"},
		{"footer CRC", footerCRC, DefaultLimits(), source.ErrCorrupt, "footer CRC32"},
		{"block CRC", blockCRC, DefaultLimits(), source.ErrCorrupt, "block CRC32"},
		{"block padding", blockPadding, DefaultLimits(), source.ErrCorrupt, "block padding"},
		{"index padding", indexPadding, DefaultLimits(), source.ErrCorrupt, "index padding"},
		{"reserved header flags", reservedHeader, DefaultLimits(), source.ErrCorrupt, "reserved flags"},
		{"reserved block flags", reservedBlock, DefaultLimits(), source.ErrCorrupt, "reserved bits"},
		{"unknown check id", unknownCheck, DefaultLimits(), source.ErrUnsupported, "check ID"},
		{"single unsupported filter", unsupportedFilter, DefaultLimits(), source.ErrUnsupported, "filter ID"},
		{"sha256 check", mustHex(t, xzSHA256Hex), DefaultLimits(), source.ErrUnsupported, "SHA-256"},
		{"crc64 check", mustHex(t, xzCRC64Hex), DefaultLimits(), source.ErrUnsupported, "CRC64"},
		{"delta filter", mustHex(t, xzDeltaHex), DefaultLimits(), source.ErrUnsupported, "filter"},
		{"bcj filter", mustHex(t, xzBCJHex), DefaultLimits(), source.ErrUnsupported, "filter"},
		{"decoded limit", text, Limits{MaxDecodedBytes: 8}, source.ErrUnsupported, "8-byte limit"},
		{"decoded limit unknown sizes", mustHex(t, xzUnknownSizesHex), Limits{MaxDecodedBytes: 8}, source.ErrUnsupported, "8-byte limit"},
		{"compressed limit", text, Limits{MaxCompressedBytes: uint64(len(text) - 1)}, source.ErrUnsupported, "compressed size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, err := openBytes(t, tc.data, tc.limits)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Open error = %v, want %v", err, tc.want)
			}
			if src != nil {
				t.Fatal("Open returned a source together with an error")
			}
			if !strings.Contains(err.Error(), tc.substr) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.substr)
			}
		})
	}
}

func TestOpenTruncatedIsCorrupt(t *testing.T) {
	text := mustHex(t, xzTextHex)
	for _, cut := range []int{1, 4, 6, 11, 12, 20, 23, 24, 30, 100, 140, 150, 160, 167} {
		t.Run("cut_"+strconv.Itoa(cut), func(t *testing.T) {
			_, err := openBytes(t, text[:cut], DefaultLimits())
			if !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("Open(%d bytes) error = %v, want ErrCorrupt", cut, err)
			}
		})
	}
}

func TestOpenIndexRecordMismatch(t *testing.T) {
	stored := mustHex(t, xzTextHex)
	indexStart := len(stored) - 24 // index + footer
	// The record's uncompressed-size VLI is 0xc4 0x01 (196); make it 197.
	if stored[indexStart+4] != 0xC4 {
		t.Fatalf("unexpected fixture layout: index byte = %#x", stored[indexStart+4])
	}
	stored[indexStart+4] = 0xC5
	indexData := stored[indexStart : indexStart+8]
	binary.LittleEndian.PutUint32(stored[indexStart+8:indexStart+12], crc32.ChecksumIEEE(indexData))

	_, err := openBytes(t, stored, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "index record") {
		t.Fatalf("error = %q, want an index-record diagnostic", err)
	}
}

func TestOpenOutputLimitExact(t *testing.T) {
	stored := mustHex(t, xzTextHex)
	src, err := openBytes(t, stored, Limits{MaxDecodedBytes: uint64(len(testText))})
	if err != nil {
		t.Fatalf("Open at the exact limit error = %v", err)
	}
	assertBytes(t, src, []byte(testText))
}

func TestSourceByteContract(t *testing.T) {
	stored := mustHex(t, xzTextHex)
	src := mustOpen(t, stored)

	if src.SourceID() != 2 || src.ImageID() != 9 || src.SectorSize() != 512 || src.IsEmpty() {
		t.Fatalf("identity = id %d image %d sector %d empty %v",
			src.SourceID(), src.ImageID(), src.SectorSize(), src.IsEmpty())
	}

	buf := make([]byte, 10)
	n, err := src.ReadAt(0, buf)
	if err != nil || n != 10 || string(buf) != testText[:10] {
		t.Fatalf("ReadAt(0,10) = %d, %v, %q", n, err, buf)
	}

	n, err = src.ReadAt(src.Len()-5, make([]byte, 10))
	if err != nil || n != 5 {
		t.Fatalf("ReadAt(short tail) = %d, %v", n, err)
	}

	if _, err := src.ReadAt(src.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt(past end) error = %v, want ErrOutOfRange", err)
	}
	if n, err := src.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("ReadAt(empty) = %d, %v", n, err)
	}
	if n, err := src.ReadAtLossy(0, buf); n != 10 || err != nil {
		t.Fatalf("ReadAtLossy = %d, %v", n, err)
	}

	stats := src.Stats()
	if stats.DecompressedBytes != uint64(len(testText)) || stats.Reads == 0 || stats.BytesRead == 0 {
		t.Fatalf("stats = %+v", stats)
	}

	extents, err := src.Extents(0, src.Len())
	if err != nil {
		t.Fatalf("Extents error = %v", err)
	}
	want := source.ParentRange{Parent: 1, ParentOffset: 0, Len: uint64(len(stored)), Kind: source.RangeData}
	if len(extents) != 1 || extents[0] != want {
		t.Fatalf("extents = %+v, want %+v", extents, want)
	}
	if _, err := src.Extents(src.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("Extents(past end) error = %v, want ErrOutOfRange", err)
	}
	if extents, err := src.Extents(0, 0); err != nil || len(extents) != 0 {
		t.Fatalf("Extents(0,0) = %+v, %v", extents, err)
	}

	out, err := src.ExtentsInto(0, src.Len(), []source.ParentRange{{Parent: 7}})
	if err != nil {
		t.Fatalf("ExtentsInto error = %v", err)
	}
	if len(out) != 2 || out[0].Parent != 7 || out[1] != want {
		t.Fatalf("ExtentsInto = %+v, want the existing entry preserved", out)
	}

	images, err := src.MapToImage(0, src.Len())
	if err != nil {
		t.Fatalf("MapToImage error = %v", err)
	}
	if len(images) != 1 || images[0].ImageID != 9 || images[0].ImageOffset != 0 ||
		images[0].Len != uint64(len(stored)) || images[0].Kind != source.RangeData {
		t.Fatalf("images = %+v", images)
	}
	if images, err := src.MapToImage(0, 0); err != nil || images != nil {
		t.Fatalf("MapToImage(0,0) = %+v, %v", images, err)
	}
	if _, err := src.MapToImage(src.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("MapToImage(past end) error = %v, want ErrOutOfRange", err)
	}
}

func TestEmptySourceContract(t *testing.T) {
	src := mustOpen(t, mustHex(t, xzEmptyHex))
	if !src.IsEmpty() || src.Len() != 0 || src.CompressedLen() != 32 {
		t.Fatalf("empty source: len %d, compressed %d", src.Len(), src.CompressedLen())
	}
	if n, err := src.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) || n != 0 {
		t.Fatalf("ReadAt on empty = %d, %v", n, err)
	}
	if extents, err := src.Extents(0, 0); err != nil || len(extents) != 0 {
		t.Fatalf("Extents(0,0) = %+v, %v", extents, err)
	}
}

// ioFailSource delegates everything except ReadAt, which fails, so the
// decoder's I/O error mapping is exercised.
type ioFailSource struct{ source.ByteSource }

func (s ioFailSource) ReadAt(offset uint64, _ []byte) (int, error) {
	return 0, source.NewIOError(offset, errors.New("backing store failed"))
}

func TestOpenPropagatesIOErrors(t *testing.T) {
	parent := ioFailSource{source.NewMemorySource(1, mustHex(t, xzTextHex))}
	_, err := Open(2, parent, DefaultLimits())
	if !errors.Is(err, source.ErrIO) {
		t.Fatalf("Open error = %v, want ErrIO", err)
	}
}

func TestDefaultLimits(t *testing.T) {
	limits := DefaultLimits()
	if limits.MaxDecodedBytes != MaxDecodedBytes || limits.MaxCompressedBytes != MaxCompressedBytes {
		t.Fatalf("DefaultLimits = %+v", limits)
	}
}

// FuzzOpen checks that arbitrary input never panics: it either decodes or
// returns an explicit error.
func FuzzOpen(f *testing.F) {
	for _, seed := range []string{xzEmptyHex, xzTextHex, xzTwoStreamsHex, xzRandomStoredHex, xzKnownPaddingHex} {
		b, err := hex.DecodeString(seed)
		if err != nil {
			f.Fatalf("bad seed: %v", err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := Limits{MaxDecodedBytes: 1 << 16, MaxCompressedBytes: 1 << 16}
		src, err := Open(2, source.NewMemorySource(1, data), limits)
		if err != nil {
			return
		}
		if src.Len() > 1<<16 {
			t.Fatalf("decoded %d bytes past the limit", src.Len())
		}
		buf := make([]byte, src.Len())
		if _, err := src.ReadAt(0, buf); err != nil {
			t.Fatalf("ReadAt on a successful decode: %v", err)
		}
		if _, err := src.Extents(0, src.Len()); err != nil {
			t.Fatalf("Extents on a successful decode: %v", err)
		}
	})
}
