package unlock

// Argon2 (RFC 9106), the memory-hard key derivation LUKS2 key slots use.
//
// The implementation follows the reference implementation step for step: H0
// parameter block, lane filling with the reference-block index function, and
// the variable-length BLAKE2b tag. Argon2id's hybrid addressing is exactly the
// "data-independent for the first half of the first pass" rule. The package
// verifies itself against the RFC 9106 vectors in argon2_test.go.
//
// Every memory or time cost comes from untrusted on-disk metadata, so it is
// bounded before a byte is allocated or a pass is run (MAX_ARGON2_*). A
// refusal is always explicit; no approximation is ever returned.

const (
	argon2BlockWords       = 128
	argon2BlockBytes       = argon2BlockWords * 8
	argon2SyncPoints       = 4
	argon2Version          = 0x13
	argon2AddressesPerBlck = 128
	argon2MinSaltBytes     = 8
	argon2MaxTagBytes      = 1024
	argon2MaxLanes         = 0x00ffffff
	argon2MaxMemoryKiB     = 4 * 1024 * 1024
)

type argon2Variant uint32

const (
	argon2D  argon2Variant = 0
	argon2I  argon2Variant = 1
	argon2ID argon2Variant = 2
)

func (v argon2Variant) name() string {
	switch v {
	case argon2D:
		return "argon2d"
	case argon2I:
		return "argon2i"
	case argon2ID:
		return "argon2id"
	default:
		return "argon2"
	}
}

func argon2VariantByName(name string) (argon2Variant, bool) {
	switch name {
	case "argon2d":
		return argon2D, true
	case "argon2i":
		return argon2I, true
	case "argon2id":
		return argon2ID, true
	default:
		return 0, false
	}
}

type argon2Params struct {
	variant   argon2Variant
	passes    uint32
	memoryKiB uint32
	lanes     uint32
	tagBytes  int
}

// argon2Blocks is the memory actually used: the cost rounded down to a whole
// number of slices per lane.
func (p argon2Params) argon2Blocks() uint64 {
	lanes := uint64(p.lanes)
	group := uint64(argon2SyncPoints) * lanes
	return uint64(p.memoryKiB) / group * group
}

func (p argon2Params) validate() error {
	if p.tagBytes < 4 || p.tagBytes > argon2MaxTagBytes {
		return argon2Errorf("a %d-byte tag is outside 4..=%d", p.tagBytes, argon2MaxTagBytes)
	}
	if p.lanes == 0 || p.lanes > argon2MaxLanes {
		return argon2Errorf("%d lane(s) is not a valid parallelism", p.lanes)
	}
	if p.passes == 0 {
		return argon2Errorf("zero passes would produce uninitialised output")
	}
	if p.memoryKiB > argon2MaxMemoryKiB {
		return argon2Errorf("%d KiB of memory exceeds the %d KiB limit", p.memoryKiB, argon2MaxMemoryKiB)
	}
	minimum := uint64(argon2SyncPoints*2) * uint64(p.lanes)
	if uint64(p.memoryKiB) < minimum {
		return argon2Errorf("%d KiB of memory is below the minimum of %d KiB for %d lane(s)",
			p.memoryKiB, minimum, p.lanes)
	}
	return nil
}

// argon2Hash computes an Argon2 tag. secret and ad are RFC 9106's optional key
// and associated data; LUKS2 uses empty slices.
func argon2Hash(params argon2Params, password, salt, secret, ad []byte) ([]byte, error) {
	if err := params.validate(); err != nil {
		return nil, err
	}
	if len(salt) < argon2MinSaltBytes {
		return nil, argon2Errorf("a %d-byte salt is shorter than the %d-byte minimum", len(salt), argon2MinSaltBytes)
	}
	blocks := params.argon2Blocks()
	if blocks > uint64(maxIntValue())/argon2BlockWords {
		return nil, argon2Errorf("%d blocks exceed the platform's address space", blocks)
	}
	memory, laneLength, err := argon2FillMemory(params, password, salt, secret, ad, params.passes)
	if err != nil {
		return nil, err
	}
	defer zeroWords(memory)

	lanes := int(params.lanes)
	last := make([]uint64, argon2BlockWords)
	base := (laneLength - 1) * argon2BlockWords
	copy(last, memory[base:base+argon2BlockWords])
	for lane := 1; lane < lanes; lane++ {
		base = (lane*laneLength + laneLength - 1) * argon2BlockWords
		for index := range last {
			last[index] ^= memory[base+index]
		}
	}
	tagInput := make([]byte, 0, argon2BlockBytes)
	for _, word := range last {
		tagInput = appendLE64(tagInput, word)
	}
	tag, ok := argon2VariableHash(tagInput, params.tagBytes)
	if !ok {
		return nil, argon2Errorf("internal variable-length hash refused its output length")
	}
	return tag, nil
}

func argon2FillMemory(params argon2Params, password, salt, secret, ad []byte, passesRun uint32) ([]uint64, int, error) {
	lanes := int(params.lanes)
	blocks := int(params.argon2Blocks())
	laneLength := blocks / lanes
	segmentLength := laneLength / argon2SyncPoints

	h0 := argon2InitialHash(params, password, salt, secret, ad)
	memory := make([]uint64, blocks*argon2BlockWords)
	for lane := 0; lane < lanes; lane++ {
		for index := 0; index < 2; index++ {
			input := make([]byte, 0, len(h0)+8)
			input = append(input, h0...)
			input = appendLE32(input, uint32(index))
			input = appendLE32(input, uint32(lane))
			block, ok := argon2VariableHash(input, argon2BlockBytes)
			if !ok {
				zeroWords(memory)
				return nil, 0, argon2Errorf("internal variable-length hash refused its output length")
			}
			base := (lane*laneLength + index) * argon2BlockWords
			for word := 0; word < argon2BlockWords; word++ {
				memory[base+word] = le64(block[word*8 : word*8+8])
			}
		}
	}
	for pass := uint32(0); pass < passesRun; pass++ {
		for slice := uint32(0); slice < argon2SyncPoints; slice++ {
			for lane := 0; lane < lanes; lane++ {
				argon2FillSegment(memory, params, lane, pass, slice, laneLength, segmentLength, blocks)
			}
		}
	}
	return memory, laneLength, nil
}

// argon2InitialHash is the 64-byte H0 of RFC 9106 section 3.2.
func argon2InitialHash(params argon2Params, password, salt, secret, ad []byte) []byte {
	hasher, _ := newBlake2b(64)
	for _, value := range []uint32{
		params.lanes,
		uint32(params.tagBytes),
		params.memoryKiB,
		params.passes,
		argon2Version,
		uint32(params.variant),
	} {
		hasher.update(appendLE32(nil, value))
	}
	for _, field := range [][]byte{password, salt, secret, ad} {
		hasher.update(appendLE32(nil, uint32(len(field))))
		hasher.update(field)
	}
	return hasher.finalize()
}

// argon2VariableHash is Argon2's H' (RFC 9106 section 3.3).
func argon2VariableHash(input []byte, outlen int) ([]byte, bool) {
	if outlen <= 64 {
		hasher, ok := newBlake2b(outlen)
		if !ok {
			return nil, false
		}
		hasher.update(appendLE32(nil, uint32(outlen)))
		hasher.update(input)
		return hasher.finalize(), true
	}
	pieces := (outlen+31)/32 - 2
	out := make([]byte, 0, outlen)
	hasher, _ := newBlake2b(64)
	hasher.update(appendLE32(nil, uint32(outlen)))
	hasher.update(input)
	chain := hasher.finalize()
	out = append(out, chain[:32]...)
	for index := 1; index < pieces; index++ {
		hasher, _ = newBlake2b(64)
		hasher.update(chain)
		chain = hasher.finalize()
		out = append(out, chain[:32]...)
	}
	tail := outlen - 32*pieces
	hasher, ok := newBlake2b(tail)
	if !ok {
		return nil, false
	}
	hasher.update(chain)
	out = append(out, hasher.finalize()...)
	return out, true
}

func argon2FillSegment(memory []uint64, params argon2Params, lane int, pass, slice uint32, laneLength, segmentLength, blocks int) {
	lanes := uint64(params.lanes)
	independent := false
	switch params.variant {
	case argon2I:
		independent = true
	case argon2ID:
		independent = pass == 0 && slice < argon2SyncPoints/2
	}

	var zero [argon2BlockWords]uint64
	var inputBlock [argon2BlockWords]uint64
	var addressBlock [argon2BlockWords]uint64
	if independent {
		inputBlock[0] = uint64(pass)
		inputBlock[1] = uint64(lane)
		inputBlock[2] = uint64(slice)
		inputBlock[3] = uint64(blocks)
		inputBlock[4] = uint64(params.passes)
		inputBlock[5] = uint64(params.variant)
	}

	startingIndex := 0
	if pass == 0 && slice == 0 {
		startingIndex = 2
	}
	curr := lane*laneLength + int(slice)*segmentLength + startingIndex
	prev := curr - 1
	if curr%laneLength == 0 {
		prev = curr + laneLength - 1
	}
	end := lane*laneLength + (int(slice)+1)*segmentLength
	index := startingIndex
	for curr < end {
		if curr%laneLength == 1 {
			prev = curr - 1
		}
		var pseudoRand uint64
		if independent {
			if index%argon2AddressesPerBlck == 0 {
				argon2NextAddresses(&inputBlock, &addressBlock, &zero)
			}
			pseudoRand = addressBlock[index%argon2AddressesPerBlck]
		} else {
			pseudoRand = memory[prev*argon2BlockWords]
		}
		refLane := int((pseudoRand >> 32) % lanes)
		if pass == 0 && slice == 0 {
			refLane = lane
		}
		refIndex := argon2IndexAlpha(
			pass, slice, index, uint32(pseudoRand&0xffffffff),
			refLane == lane, laneLength, segmentLength,
		)
		refOffset := (refLane*laneLength + refIndex) * argon2BlockWords
		currOffset := curr * argon2BlockWords
		previousOffset := prev * argon2BlockWords

		var reference [argon2BlockWords]uint64
		copy(reference[:], memory[refOffset:refOffset+argon2BlockWords])
		var previous [argon2BlockWords]uint64
		copy(previous[:], memory[previousOffset:previousOffset+argon2BlockWords])

		argon2FillBlock(previous[:], reference[:], memory[currOffset:currOffset+argon2BlockWords], pass > 0)

		curr++
		prev = curr - 1
		index++
	}
}

// argon2IndexAlpha is the reference-index function of RFC 9106 section 3.4.1.2.
func argon2IndexAlpha(pass, slice uint32, index int, pseudoRand uint32, sameLane bool, laneLength, segmentLength int) int {
	var startPosition int
	var area int64
	if pass == 0 {
		switch {
		case slice == 0:
			area = int64(index) - 1
		case sameLane:
			area = int64(slice)*int64(segmentLength) + int64(index) - 1
		default:
			area = int64(slice) * int64(segmentLength)
			if index == 0 {
				area--
			}
		}
	} else {
		if slice == argon2SyncPoints-1 {
			startPosition = 0
		} else {
			startPosition = (int(slice) + 1) * segmentLength
		}
		if sameLane {
			area = int64(laneLength) - int64(segmentLength) + int64(index) - 1
		} else {
			area = int64(laneLength) - int64(segmentLength)
			if index == 0 {
				area--
			}
		}
	}
	if area < 0 {
		area = 0
	}
	relative := uint64(pseudoRand)
	relative = (relative * relative) >> 32
	relative = uint64(area) - 1 - ((uint64(area) * relative) >> 32)
	return (startPosition + int(relative)) % laneLength
}

func argon2NextAddresses(inputBlock, addressBlock, zero *[argon2BlockWords]uint64) {
	inputBlock[6]++
	var first [argon2BlockWords]uint64
	argon2FillBlock(zero[:], inputBlock[:], first[:], false)
	argon2FillBlock(zero[:], first[:], addressBlock[:], false)
}

// argon2FillBlock is one block compression (RFC 9106 section 3.5).
func argon2FillBlock(previous, reference, next []uint64, withXor bool) {
	var blockR [argon2BlockWords]uint64
	var saved [argon2BlockWords]uint64
	for index := 0; index < argon2BlockWords; index++ {
		blockR[index] = previous[index] ^ reference[index]
		saved[index] = blockR[index]
	}
	if withXor {
		for index := 0; index < argon2BlockWords; index++ {
			saved[index] ^= next[index]
		}
	}
	for group := 0; group < 8; group++ {
		var words [16]uint64
		copy(words[:], blockR[group*16:group*16+16])
		argon2Round(&words)
		copy(blockR[group*16:group*16+16], words[:])
	}
	for group := 0; group < 8; group++ {
		var words [16]uint64
		for pair := 0; pair < 8; pair++ {
			words[pair*2] = blockR[group*2+pair*16]
			words[pair*2+1] = blockR[group*2+pair*16+1]
		}
		argon2Round(&words)
		for pair := 0; pair < 8; pair++ {
			blockR[group*2+pair*16] = words[pair*2]
			blockR[group*2+pair*16+1] = words[pair*2+1]
		}
	}
	for index := 0; index < argon2BlockWords; index++ {
		next[index] = saved[index] ^ blockR[index]
	}
}

// argon2Round is BLAKE2_ROUND_NOMSG from the reference implementation.
func argon2Round(words *[16]uint64) {
	argon2G(words, 0, 4, 8, 12)
	argon2G(words, 1, 5, 9, 13)
	argon2G(words, 2, 6, 10, 14)
	argon2G(words, 3, 7, 11, 15)
	argon2G(words, 0, 5, 10, 15)
	argon2G(words, 1, 6, 11, 12)
	argon2G(words, 2, 7, 8, 13)
	argon2G(words, 3, 4, 9, 14)
}

// argon2G is BLAKE2b's G with the BlaMka multiplication.
func argon2G(words *[16]uint64, a, b, c, d int) {
	words[a] = argon2Blamka(words[a], words[b])
	words[d] = rotateRight64(words[d]^words[a], 32)
	words[c] = argon2Blamka(words[c], words[d])
	words[b] = rotateRight64(words[b]^words[c], 24)
	words[a] = argon2Blamka(words[a], words[b])
	words[d] = rotateRight64(words[d]^words[a], 16)
	words[c] = argon2Blamka(words[c], words[d])
	words[b] = rotateRight64(words[b]^words[c], 63)
}

func argon2Blamka(x, y uint64) uint64 {
	return x + y + 2*uint64(uint32(x))*uint64(uint32(y))
}

func appendLE32(out []byte, value uint32) []byte {
	return append(out, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

func zeroWords(words []uint64) {
	for index := range words {
		words[index] = 0
	}
}

func maxIntValue() int { return int(^uint(0) >> 1) }
