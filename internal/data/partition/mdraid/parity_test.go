package mdraid

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func buildParityMembers(t *testing.T, level int32, layout uint32, disks int, chunkBytes uint64, chunksPerMember int) ([]ArrayMember, []byte) {
	t.Helper()
	parityDisks := 1
	if level == 6 {
		parityDisks = 2
	}
	dataDisks := disks - parityDisks
	componentBytes := chunkBytes * uint64(chunksPerMember)

	arrays := make([][]byte, disks)
	for i := range arrays {
		arrays[i] = make([]byte, componentBytes)
	}

	logicalChunks := chunksPerMember * dataDisks
	logical := make([]byte, uint64(logicalChunks)*chunkBytes)
	for c := 0; c < logicalChunks; c++ {
		pattern := byte('A' + c%26)
		for i := uint64(0); i < chunkBytes; i++ {
			logical[uint64(c)*chunkBytes+i] = pattern
		}
		st := parityStripe(level, layout, uint64(c), uint64(disks), uint64(dataDisks))
		off := st.memberChunk * chunkBytes
		copy(arrays[st.data][off:off+chunkBytes], logical[uint64(c)*chunkBytes:])
	}

	for stripeIndex := 0; stripeIndex < chunksPerMember; stripeIndex++ {
		rep := uint64(stripeIndex) * uint64(dataDisks)
		st := parityStripe(level, layout, rep, uint64(disks), uint64(dataDisks))
		off := uint64(stripeIndex) * chunkBytes

		dataRoles := make([]uint64, dataDisks)
		for d := 0; d < dataDisks; d++ {
			chunkIndex := uint64(stripeIndex)*uint64(dataDisks) + uint64(d)
			ds := parityStripe(level, layout, chunkIndex, uint64(disks), uint64(dataDisks))
			dataRoles[d] = ds.data
		}

		p := make([]byte, chunkBytes)
		q := make([]byte, chunkBytes)
		var slots []int
		if level == 6 {
			slots = raid6Slots(disks, st.pd, uint64(st.qd))
		}
		for _, role := range dataRoles {
			chunk := arrays[role][off : off+chunkBytes]
			for i := range chunk {
				p[i] ^= chunk[i]
			}
			if level == 6 {
				coefficient := gfPow(uint64(slots[role]))
				for i := range chunk {
					q[i] ^= gfMul(coefficient, chunk[i])
				}
			}
		}
		copy(arrays[st.pd][off:off+chunkBytes], p)
		if level == 6 {
			qd := uint64(st.qd)
			copy(arrays[qd][off:off+chunkBytes], q)
		}
	}

	members := make([]ArrayMember, disks)
	chunkSectors := uint32(chunkBytes / 512)
	for dev := 0; dev < disks; dev++ {
		sb := buildSB1WithLayout(t, level, layout, chunkSectors, uint32(disks), uint32(dev),
			uint16(dev), 16, componentBytes/512, uint32(disks))
		image := imageWithSB1(sb, 16, make([]byte, componentBytes))
		parsed, err := Parse(source.NewMemorySource(99, image))
		if err != nil || parsed == nil {
			t.Fatalf("parity member %d: %+v, %v", dev, parsed, err)
		}
		members[dev] = ArrayMember{
			Superblock: parsed,
			Data:       source.NewMemorySource(source.ID(dev+1), arrays[dev]),
		}
	}
	return members, logical
}

func withoutRoles(members []ArrayMember, roles ...int) []ArrayMember {
	drop := make(map[int]bool, len(roles))
	for _, role := range roles {
		drop[role] = true
	}
	out := make([]ArrayMember, 0, len(members))
	for i, member := range members {
		if !drop[i] {
			out = append(out, member)
		}
	}
	return out
}

func readArrayAndCompare(t *testing.T, array *ArraySource, want []byte) {
	t.Helper()
	buf := make([]byte, array.Len())
	n, err := array.ReadAt(0, buf)
	if err != nil {
		t.Fatalf("ReadAt error = %v", err)
	}
	if n != len(buf) {
		t.Fatalf("ReadAt n = %d, want %d", n, len(buf))
	}
	if !bytes.Equal(buf, want) {
		for i := range buf {
			if buf[i] != want[i] {
				t.Fatalf("byte %d = %q, want %q", i, buf[i], want[i])
			}
		}
	}
}

func TestGFKnownValues(t *testing.T) {
	if got := gfMulSlow(0x80, 2); got != 0x1D {
		t.Fatalf("gfMulSlow(0x80, 2) = %#x, want 0x1D", got)
	}
	if got := gfMul(0, 5); got != 0 {
		t.Fatalf("gfMul(0, 5) = %#x", got)
	}
	if got := gfMul(1, 0x53); got != 0x53 {
		t.Fatalf("gfMul(1, 0x53) = %#x", got)
	}
	if got := gfPow(0); got != 1 {
		t.Fatalf("gfPow(0) = %#x", got)
	}
	value := gfPow(5)
	if got := gfMul(value, gfInv(value)); got != 1 {
		t.Fatalf("g^5 * (g^5)^-1 = %#x, want 1", got)
	}
}

func TestParityStripeLeftAsymmetric(t *testing.T) {
	// RAID5, 3 members, 2 data disks.
	cases := []struct {
		chunkIndex  uint64
		data, pd    uint64
		memberChunk uint64
	}{
		{0, 0, 2, 0},
		{1, 1, 2, 0},
		{2, 0, 1, 1},
		{3, 2, 1, 1},
	}
	for _, tc := range cases {
		got := parityStripe(5, algorithmLeftAsymmetric, tc.chunkIndex, 3, 2)
		if got.data != tc.data || got.pd != tc.pd || got.memberChunk != tc.memberChunk || got.qd != -1 {
			t.Fatalf("RAID5 chunk %d = %+v, want data=%d pd=%d chunk=%d",
				tc.chunkIndex, got, tc.data, tc.pd, tc.memberChunk)
		}
	}

	// RAID6, 4 members, 2 data disks: stripe 0 puts Q at 0 and P at 3.
	got := parityStripe(6, algorithmLeftAsymmetric, 0, 4, 2)
	if got.data != 1 || got.pd != 3 || got.qd != 0 || got.memberChunk != 0 {
		t.Fatalf("RAID6 chunk 0 = %+v", got)
	}
	got = parityStripe(6, algorithmLeftAsymmetric, 3, 4, 2)
	if got.data != 1 || got.pd != 2 || got.qd != 3 || got.memberChunk != 1 {
		t.Fatalf("RAID6 chunk 3 = %+v", got)
	}
}

func TestRaid5CompleteAndDegraded(t *testing.T) {
	const chunk = 64 * 1024
	members, logical := buildParityMembers(t, 5, algorithmLeftAsymmetric, 3, chunk, 2)

	array, err := Raid456(7, members)
	if err != nil {
		t.Fatalf("Raid456(complete) error = %v", err)
	}
	if array.Len() != uint64(len(logical)) {
		t.Fatalf("Len = %d, want %d", array.Len(), len(logical))
	}
	readArrayAndCompare(t, array, logical)

	for _, missing := range []int{0, 1, 2} {
		degraded, err := Raid456(7, withoutRoles(members, missing))
		if err != nil {
			t.Fatalf("Raid456(missing %d) error = %v", missing, err)
		}
		readArrayAndCompare(t, degraded, logical)
		if got := degraded.MissingRoles(); len(got) != 1 || int(got[0]) != missing {
			t.Fatalf("MissingRoles = %v, want [%d]", got, missing)
		}
	}
}

func TestRaid5RefusesTwoMissingMembers(t *testing.T) {
	members, _ := buildParityMembers(t, 5, algorithmLeftAsymmetric, 3, 64*1024, 2)
	if _, err := Raid456(7, withoutRoles(members, 0, 1)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Raid456 error = %v, want ErrUnsupported", err)
	}
}

func TestRaid6TwoDataGapsUsePAndQ(t *testing.T) {
	const chunk = 64 * 1024
	members, logical := buildParityMembers(t, 6, algorithmLeftAsymmetric, 4, chunk, 2)

	array, err := Raid456(7, members)
	if err != nil {
		t.Fatalf("Raid456(complete) error = %v", err)
	}
	readArrayAndCompare(t, array, logical)

	// Roles 0 and 1: stripe 0 loses Q and one data chunk (P suffices), while
	// stripe 1 loses both data chunks (P and Q together).
	degraded, err := Raid456(7, withoutRoles(members, 0, 1))
	if err != nil {
		t.Fatalf("Raid456(two gaps) error = %v", err)
	}
	readArrayAndCompare(t, degraded, logical)
}

func TestRaid6DataPlusPRecoversFromQ(t *testing.T) {
	const chunk = 64 * 1024
	members, logical := buildParityMembers(t, 6, algorithmLeftAsymmetric, 4, chunk, 2)

	// Roles 1 and 3: stripe 0 loses a data chunk and P (Q alone recovers);
	// stripe 1 loses a data chunk and Q (P alone recovers).
	degraded, err := Raid456(7, withoutRoles(members, 1, 3))
	if err != nil {
		t.Fatalf("Raid456(two gaps) error = %v", err)
	}
	readArrayAndCompare(t, degraded, logical)
}

func TestRaid6RefusesDDFTwoGap(t *testing.T) {
	members, _ := buildParityMembers(t, 6, algorithmRotatingZeroStart, 4, 64*1024, 2)
	if _, err := Raid456(7, withoutRoles(members, 0, 1)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Raid456 error = %v, want ErrUnsupported", err)
	}
}
