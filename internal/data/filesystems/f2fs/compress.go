package f2fs

// Compressed-cluster format constants.
const (
	// CompressMagic is the four bytes every compressed cluster header starts
	// with.
	CompressMagic uint32 = 0xF2F52010
	// CompressHeaderSize is the header at the front of a cluster's stored
	// stream.
	CompressHeaderSize = 24
	// AlgorithmLZO is the plain LZO1X block format.
	AlgorithmLZO uint8 = 0
	// AlgorithmLZ4 is one raw LZ4 block.
	AlgorithmLZ4 uint8 = 1
	// AlgorithmZSTD is one Zstandard frame.
	AlgorithmZSTD uint8 = 2
	// AlgorithmLZORLE is LZO1X with the run-length extension.
	AlgorithmLZORLE uint8 = 3
	// MaxClusterLog is the largest i_log_cluster_size this reader accepts.
	MaxClusterLog uint8 = 8
	// MaxDecompressed is the most bytes one read request may decompress.
	MaxDecompressed uint64 = 16 << 20
)

// AlgorithmName returns the algorithm's name, as an error message uses it.
func AlgorithmName(algorithm uint8) string {
	switch algorithm {
	case AlgorithmLZO:
		return "LZO"
	case AlgorithmLZ4:
		return "LZ4"
	case AlgorithmZSTD:
		return "ZSTD"
	case AlgorithmLZORLE:
		return "LZORLE"
	default:
		return "an unknown algorithm"
	}
}

// ClusterHeader is a parsed and cross-checked compressed cluster header.
type ClusterHeader struct {
	// ClusterStart is the logical block index the cluster starts at.
	ClusterStart uint64
	// Clen is the compressed payload length that follows the header.
	Clen uint32
	// ClusterBytes is the cluster's declared size in bytes.
	ClusterBytes uint32
	// Algorithm is the algorithm byte the header carries.
	Algorithm uint8
}

// ParseClusterHeader reads and cross-checks the header at the front of a
// cluster's first stored block.
func ParseClusterHeader(firstBlock []byte, blockSize uint32, logClusterSize uint8, inodeAlgorithm uint8, clusterStart uint64) (*ClusterHeader, error) {
	if blockSize == 0 || blockSize&(blockSize-1) != 0 {
		return nil, invalidf("the volume block size %d cannot bound a compressed cluster", blockSize)
	}
	if logClusterSize == 0 || logClusterSize > MaxClusterLog {
		return nil, invalidf("the compressed cluster at block %d needs a cluster log size between 1 and %d, not %d",
			clusterStart, MaxClusterLog, logClusterSize)
	}
	if len(firstBlock) < CompressHeaderSize {
		return nil, invalidf("the compressed cluster at block %d has %d header bytes, fewer than the %d a cluster header occupies",
			clusterStart, len(firstBlock), CompressHeaderSize)
	}
	magic, err := u32At(firstBlock, 0)
	if err != nil {
		return nil, err
	}
	if magic != CompressMagic {
		return nil, invalidf("the compressed cluster at block %d starts with magic %#010x, not F2FS_COMPRESS_MAGIC %#010x",
			clusterStart, magic, CompressMagic)
	}
	clen, err := u32At(firstBlock, 4)
	if err != nil {
		return nil, err
	}
	clusterBytes, err := u32At(firstBlock, 8)
	if err != nil {
		return nil, err
	}
	algorithm, err := u8At(firstBlock, 12)
	if err != nil {
		return nil, err
	}
	expected := uint64(blockSize) << logClusterSize
	if uint64(clusterBytes) != expected {
		return nil, invalidf("the compressed cluster at block %d declares a %d-byte cluster, but the volume's %d-byte blocks and the inode's cluster log %d make %d",
			clusterStart, clusterBytes, blockSize, logClusterSize, expected)
	}
	if algorithm != inodeAlgorithm {
		return nil, invalidf("the compressed cluster at block %d names algorithm %d (%s), but the inode was written with %d (%s)",
			clusterStart, algorithm, AlgorithmName(algorithm), inodeAlgorithm, AlgorithmName(inodeAlgorithm))
	}
	if clen == 0 {
		return nil, invalidf("the compressed cluster at block %d declares no payload", clusterStart)
	}
	clusterBlocks := uint64(1) << logClusterSize
	capacity := (clusterBlocks - 1) * uint64(blockSize)
	stored := uint64(CompressHeaderSize) + uint64(clen)
	if stored > capacity {
		return nil, invalidf("the compressed cluster at block %d holds %d bytes, more than the %d its %d stored blocks can carry",
			clusterStart, stored, capacity, clusterBlocks-1)
	}
	return &ClusterHeader{
		ClusterStart: clusterStart,
		Clen:         clen,
		ClusterBytes: clusterBytes,
		Algorithm:    algorithm,
	}, nil
}

// StoredBlocks returns the stored blocks the header and payload occupy.
func (h *ClusterHeader) StoredBlocks(blockSize uint32) uint64 {
	return (uint64(CompressHeaderSize) + uint64(h.Clen) + uint64(blockSize) - 1) / uint64(blockSize)
}

// DecodeCluster decodes one cluster's payload into exactly its declared size.
//
// LZ4 blocks are decoded here.  LZO, LZORLE and Zstandard clusters are refused
// by name: this build has no decode dependency for them, and guessing a
// neighbouring format would serve wrong bytes.
func DecodeCluster(header *ClusterHeader, payload []byte) ([]byte, error) {
	expected := int(header.ClusterBytes)
	switch header.Algorithm {
	case AlgorithmLZ4:
		decoded, err := decodeLZ4Block(payload, expected)
		if err != nil {
			return nil, invalidf("the LZ4-compressed cluster at block %d is broken: %v", header.ClusterStart, err)
		}
		if len(decoded) != expected {
			return nil, invalidf("the compressed cluster at block %d decoded to %d bytes, not the %d the cluster declares",
				header.ClusterStart, len(decoded), expected)
		}
		return decoded, nil
	case AlgorithmLZO:
		return nil, unsupportedf("the LZO-compressed cluster at block %d, whose LZO1X decoder is not ported", header.ClusterStart)
	case AlgorithmZSTD:
		return nil, unsupportedf("the ZSTD-compressed cluster at block %d, whose Zstandard decoder is not ported", header.ClusterStart)
	case AlgorithmLZORLE:
		return nil, unsupportedf("the LZORLE-compressed cluster at block %d, whose run-length extension this reader does not decode", header.ClusterStart)
	default:
		return nil, unsupportedf("the compression algorithm %d of the cluster at block %d", header.Algorithm, header.ClusterStart)
	}
}

// decodeLZ4Block decodes one raw LZ4 block into exactly expected bytes.
func decodeLZ4Block(input []byte, expected int) ([]byte, error) {
	out := make([]byte, 0, expected)
	at := 0
	for at < len(input) {
		token := input[at]
		at++
		literals := int(token >> 4)
		if literals == 15 {
			for {
				if at >= len(input) {
					return nil, errString("the block ends inside a literal-length run")
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
			if at+literals > len(input) {
				return nil, errString("the block ends inside a literal run")
			}
			if len(out)+literals > expected {
				return nil, errString("the block decodes past the declared size")
			}
			out = append(out, input[at:at+literals]...)
			at += literals
		}
		// A block's final sequence carries literals only.
		if at >= len(input) {
			break
		}
		if at+2 > len(input) {
			return nil, errString("the block ends before a match offset")
		}
		offset := int(uint16(input[at]) | uint16(input[at+1])<<8)
		at += 2
		if offset == 0 || offset > len(out) {
			return nil, errString("a match offset reaches before the decoded bytes")
		}
		length := int(token & 0x0f)
		if length == 15 {
			for {
				if at >= len(input) {
					return nil, errString("the block ends inside a match-length run")
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
		if len(out)+length > expected {
			return nil, errString("the block decodes past the declared size")
		}
		for index := 0; index < length; index++ {
			out = append(out, out[len(out)-offset])
		}
	}
	if len(out) != expected {
		return nil, errString("the block decoded fewer bytes than its declared size")
	}
	return out, nil
}

type errString string

func (e errString) Error() string { return string(e) }
