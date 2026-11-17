package pst

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func openData(t *testing.T, data []byte) *Reader {
	t.Helper()
	reader, err := Open(source.NewMemorySource(1, data), DefaultLimits())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return reader
}

func requireText(t *testing.T, value *string, expected, field string) {
	t.Helper()
	if value == nil {
		t.Fatalf("%s is absent, want %q", field, expected)
	}
	if *value != expected {
		t.Fatalf("%s = %q, want %q", field, *value, expected)
	}
}

func messageByNID(t *testing.T, messages []Message, nid uint64) *Message {
	t.Helper()
	for index := range messages {
		if messages[index].NID == nid {
			return &messages[index]
		}
	}
	t.Fatalf("no message with NID 0x%X", nid)
	return nil
}

func expectedSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func TestMatchesSignature(t *testing.T) {
	good := append([]byte("!BDN\x00\x00\x00\x00SM"), make([]byte, 16)...)
	if !MatchesSignature(good) {
		t.Fatal("MatchesSignature rejected a PST signature")
	}
	ost := append([]byte("!BDN\x00\x00\x00\x00SO"), make([]byte, 16)...)
	if !MatchesSignature(ost) {
		t.Fatal("MatchesSignature rejected an OST signature")
	}
	if MatchesSignature([]byte("!BDN")) {
		t.Fatal("MatchesSignature accepted a short buffer")
	}
	if MatchesSignature([]byte("!BDN\x00\x00\x00\x00XX")) {
		t.Fatal("MatchesSignature accepted an unknown content magic")
	}
}

func TestWalkUnicode512(t *testing.T) {
	fixture := buildMainFixture(FormatUnicode512, CryptNone, false)
	reader := openData(t, fixture.build())

	header := reader.Header()
	if header.Version != 23 || header.Format != FormatUnicode512 || header.ContentType != StorePersonal {
		t.Fatalf("header = %+v", header)
	}
	if header.PageBytes != 512 || header.CryptMethod != CryptNone {
		t.Fatalf("header page bytes/crypt = %d/%v", header.PageBytes, header.CryptMethod)
	}
	if header.VersionClient != 23 {
		t.Fatalf("header client version = %d", header.VersionClient)
	}
	stats := reader.Stats()
	if stats.NodeCount != 5 || stats.FolderNodes != 2 || stats.MessageNodes != 2 || stats.AssociatedMessageNodes != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.ChecksumMismatches != 0 {
		t.Fatalf("checksum mismatches = %d", stats.ChecksumMismatches)
	}

	folders, err := reader.Folders()
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	if len(folders) != 2 {
		t.Fatalf("folders = %d, want 2", len(folders))
	}
	var root, inbox *Folder
	for index := range folders {
		switch folders[index].NID {
		case 0x22:
			root = &folders[index]
		case 0x42:
			inbox = &folders[index]
		}
	}
	if root == nil || inbox == nil {
		t.Fatalf("missing root or Inbox folder: %+v", folders)
	}
	requireText(t, root.Name, "Root", "root name")
	requireText(t, inbox.Name, "Inbox", "inbox name")
	if inbox.ContentCount == nil || *inbox.ContentCount != 2 {
		t.Fatalf("Inbox content count = %v", inbox.ContentCount)
	}
	if inbox.MessageCount != 2 {
		t.Fatalf("Inbox message count = %d, want 2", inbox.MessageCount)
	}
	if root.MessageCount != 0 {
		t.Fatalf("root message count = %d, want 0", root.MessageCount)
	}
	if len(root.ChildFolders) != 1 || root.ChildFolders[0] != 0x42 {
		t.Fatalf("root children = %v", root.ChildFolders)
	}
	if root.DataOffset == 0 || root.PageOffset == 0 {
		t.Fatalf("folder provenance = offset %d page %d", root.DataOffset, root.PageOffset)
	}

	messages, err := reader.Messages()
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(messages) != 3 {
		t.Fatalf("messages = %d, want 3", len(messages))
	}
	message := messageByNID(t, messages, 0x1004)
	requireText(t, message.Subject, "Quarterly numbers", "subject")
	requireText(t, message.SenderName, "Alice", "sender name")
	requireText(t, message.SenderEmail, "alice@example.com", "sender email")
	if message.SenderEmailSource != "smtp-address" {
		t.Fatalf("sender source = %q", message.SenderEmailSource)
	}
	requireText(t, message.MessageClass, "IPM.Note", "message class")
	requireText(t, message.Body, "Hello body", "body")
	requireText(t, message.TransportHeaders, "Café", "transport headers")
	requireText(t, message.MessageID, "<id@example>", "message id")
	if string(message.HTML) != "<html>x</html>" {
		t.Fatalf("html = %q", message.HTML)
	}
	if string(message.RTF) != string(referenceRTFStream()) {
		t.Fatalf("rtf property was not preserved byte-for-byte")
	}
	if message.Size == nil || *message.Size != 1234 {
		t.Fatalf("size = %v", message.Size)
	}
	if message.Flags == nil || *message.Flags != 0x20 {
		t.Fatalf("flags = %v", message.Flags)
	}
	if message.SubmitTime == nil || *message.SubmitTime != Filetime(132000000000000000) {
		t.Fatalf("submit time = %v", message.SubmitTime)
	}
	if message.DeliveryTime == nil || *message.DeliveryTime != Filetime(132000000000000001) {
		t.Fatalf("delivery time = %v", message.DeliveryTime)
	}
	if len(message.DisplayTo) != 2 || message.DisplayTo[0] != "Bob" || message.DisplayTo[1] != "Carol" {
		t.Fatalf("display to = %v", message.DisplayTo)
	}
	if message.HasAttachments == nil || !*message.HasAttachments {
		t.Fatalf("has attachments = %v", message.HasAttachments)
	}
	if message.DataOffset == 0 || message.PageOffset != 1024 || message.SubnodeBID == 0 {
		t.Fatalf("message provenance = %+v", message)
	}

	associated := messageByNID(t, messages, 0x1008)
	if !associated.Associated {
		t.Fatal("associated message not marked")
	}
	if associated.Body != nil {
		t.Fatalf("associated body = %q, want absent", *associated.Body)
	}
	empty := messageByNID(t, messages, 0x1024)
	if empty.Body == nil || *empty.Body != "" {
		t.Fatalf("stored empty body = %v, want pointer to empty string", empty.Body)
	}

	properties, err := reader.Properties(0x1004)
	if err != nil {
		t.Fatalf("Properties: %v", err)
	}
	var unsupported *Property
	for index := range properties {
		if properties[index].ID == 0x7FFF {
			unsupported = &properties[index]
		}
	}
	if unsupported == nil {
		t.Fatal("unsupported property missing")
	}
	if unsupported.Value.Kind != ValueUnsupported || unsupported.Value.UnsupportedKind != 0x1234 || unsupported.Value.UnsupportedLen != 5 {
		t.Fatalf("unsupported property = %+v", unsupported.Value)
	}

	attachments, present, err := reader.Attachments(0x1004)
	if err != nil {
		t.Fatalf("Attachments: %v", err)
	}
	if !present || len(attachments) != 1 {
		t.Fatalf("attachments present=%v rows=%d", present, len(attachments))
	}
	attachment := attachments[0]
	if attachment.NID != 0x2001 || attachment.Index != 0 {
		t.Fatalf("attachment id/index = %#x/%d", attachment.NID, attachment.Index)
	}
	requireText(t, attachment.Filename, "report.pdf", "attachment filename")
	requireText(t, attachment.Extension, "pdf", "attachment extension")
	requireText(t, attachment.MIMEType, "application/pdf", "attachment MIME")
	requireText(t, attachment.ContentID, "cid-1", "attachment content id")
	if attachment.Method == nil || *attachment.Method != 1 {
		t.Fatalf("attachment method = %v", attachment.Method)
	}
	if attachment.Size == nil || *attachment.Size != 5 {
		t.Fatalf("attachment size = %v", attachment.Size)
	}
	if attachment.DataBytes == nil || *attachment.DataBytes != 5 {
		t.Fatalf("attachment data bytes = %v", attachment.DataBytes)
	}
	if attachment.SHA256 == nil || *attachment.SHA256 != expectedSHA256("hello") {
		t.Fatalf("attachment sha256 = %v", attachment.SHA256)
	}
	if attachment.DataProblem != nil {
		t.Fatalf("attachment data problem = %q", *attachment.DataProblem)
	}
	if attachment.ObjectBID == 0 || attachment.ObjectOffset == 0 {
		t.Fatalf("attachment provenance = bid 0x%X offset %d", attachment.ObjectBID, attachment.ObjectOffset)
	}
	if attachment.Created == nil || *attachment.Created != Filetime(132000000000000002) {
		t.Fatalf("attachment created = %v", attachment.Created)
	}

	recipients, present, err := reader.Recipients(0x1004)
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	if !present || len(recipients) != 2 {
		t.Fatalf("recipients present=%v rows=%d", present, len(recipients))
	}
	first := recipients[0]
	if first.RowID != 0x0601 {
		t.Fatalf("recipient row id = %#x", first.RowID)
	}
	requireText(t, first.DisplayName, "Alice", "recipient name")
	requireText(t, first.AddressType, "SMTP", "recipient address type")
	requireText(t, first.Email, "alice@example.com", "recipient email")
	requireText(t, first.SMTP, "alice@example.com", "recipient smtp")
	if first.Kind == nil || *first.Kind != 1 {
		t.Fatalf("recipient kind = %v", first.Kind)
	}
	if first.Problem != nil {
		t.Fatalf("recipient problem = %q", *first.Problem)
	}
	second := recipients[1]
	requireText(t, second.DisplayName, "Bob", "second recipient name")
	if second.Kind == nil || *second.Kind != 2 {
		t.Fatalf("second recipient kind = %v", second.Kind)
	}

	if _, present, err := reader.Attachments(0x1008); err != nil || present {
		t.Fatalf("associated message attachment table present=%v err=%v", present, err)
	}
	if _, present, err := reader.Recipients(0x1008); err != nil || present {
		t.Fatalf("associated message recipient table present=%v err=%v", present, err)
	}

	recovery, err := reader.RecoverDeleted()
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}
	if len(recovery.Messages) != 0 || len(recovery.Refusals) != 0 || len(recovery.Problems) != 0 {
		t.Fatalf("recovery on a complete store = %+v", recovery)
	}

	maps, err := reader.AllocationMaps()
	if err != nil {
		t.Fatalf("AllocationMaps: %v", err)
	}
	if len(maps) != 2 {
		t.Fatalf("allocation maps = %d, want 2", len(maps))
	}
	amap, pmap := maps[0], maps[1]
	if amap.Kind != MapAMap || amap.Offset != 0x4400 || amap.BID != 0x4400 {
		t.Fatalf("AMap = %+v", amap)
	}
	if len(amap.Bits) != 496 || amap.UnitBytes != 64 || amap.MappedStart != 0x4400 {
		t.Fatalf("AMap geometry = %+v", amap)
	}
	if !amap.Allocated(0) || amap.Allocated(8) {
		t.Fatalf("AMap bits were not parsed")
	}
	if pmap.Kind != MapPMap || pmap.Offset != 0x4600 || pmap.UnitBytes != 512 {
		t.Fatalf("PMap = %+v", pmap)
	}
}

func TestFormatsAndEncryption(t *testing.T) {
	cases := []struct {
		name     string
		format   StoreFormat
		crypt    CryptMethod
		compress bool
	}{
		{"unicode512-none", FormatUnicode512, CryptNone, false},
		{"unicode512-permute", FormatUnicode512, CryptPermute, false},
		{"unicode512-cyclic", FormatUnicode512, CryptCyclic, false},
		{"ansi-none", FormatAnsi, CryptNone, false},
		{"ansi-permute", FormatAnsi, CryptPermute, false},
		{"ansi-cyclic", FormatAnsi, CryptCyclic, false},
		{"unicode4k-none-zlib", FormatUnicode4K, CryptNone, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := buildMainFixture(testCase.format, testCase.crypt, testCase.compress)
			reader := openData(t, fixture.build())
			header := reader.Header()
			if header.Format != testCase.format || header.CryptMethod != testCase.crypt {
				t.Fatalf("header = %+v", header)
			}
			if header.PageBytes != testCase.format.PageBytes() {
				t.Fatalf("page bytes = %d", header.PageBytes)
			}
			messages, err := reader.Messages()
			if err != nil {
				t.Fatalf("Messages: %v", err)
			}
			message := messageByNID(t, messages, 0x1004)
			requireText(t, message.Subject, "Quarterly numbers", "subject")
			requireText(t, message.Body, "Hello body", "body")
			requireText(t, message.TransportHeaders, "Café", "transport headers")
			attachments, present, err := reader.Attachments(0x1004)
			if err != nil || !present || len(attachments) != 1 {
				t.Fatalf("Attachments present=%v err=%v", present, err)
			}
			if attachments[0].SHA256 == nil || *attachments[0].SHA256 != expectedSHA256("hello") {
				t.Fatalf("attachment sha256 = %v", attachments[0].SHA256)
			}
			if testCase.format == FormatAnsi {
				properties, err := reader.Properties(0x22)
				if err != nil {
					t.Fatalf("Properties: %v", err)
				}
				var display *Property
				for index := range properties {
					if properties[index].ID == propDisplayName {
						display = &properties[index]
					}
				}
				if display == nil || display.TextBasis == nil || display.TextBasis.BytesPreserved || display.TextBasis.CodePage != 1252 {
					t.Fatalf("ANSI text basis = %+v", display)
				}
			}
			if testCase.compress {
				compressed := false
				for _, block := range fixture.blocks {
					if block.original > block.cb {
						compressed = true
					}
				}
				if !compressed {
					t.Fatal("no block was stored as a zlib stream")
				}
			}
			_ = reader.ChecksumMismatches()
		})
	}
}

func TestTwoLevelArray(t *testing.T) {
	fixture := buildTwoLevelArrayFixture()
	reader := openData(t, fixture.build())
	data, err := reader.NodeData(0x1004)
	if err != nil {
		t.Fatalf("NodeData: %v", err)
	}
	if string(data) != "hello world" {
		t.Fatalf("node data = %q", data)
	}
	if reader.BlockCount() != 4 {
		t.Fatalf("blocks = %d, want 4", reader.BlockCount())
	}
}

func TestHeaderAndEncryptionRefusals(t *testing.T) {
	base := buildMainFixture(FormatUnicode512, CryptNone, false).build()
	cases := []struct {
		name   string
		mutate func([]byte)
		kind   error
		needle string
	}{
		{"signature", func(data []byte) { data[0] = 'X' }, source.ErrCorrupt, "signature"},
		{"content-magic", func(data []byte) { data[8], data[9] = 'X', 'X' }, source.ErrCorrupt, "content magic"},
		{"sentinel", func(data []byte) { data[512] = 0 }, source.ErrCorrupt, "sentinel"},
		{"file-eof", func(data []byte) { putU64(data, 184, uint64(len(data)+1)) }, source.ErrCorrupt, "declares"},
		{"version-21", func(data []byte) { putU16(data, 10, 21) }, source.ErrUnsupported, "version 21"},
		{"version-37", func(data []byte) { putU16(data, 10, 37) }, source.ErrUnsupported, "WIP"},
		{"strong-encryption", func(data []byte) { data[513] = 3 }, source.ErrUnsupported, "strong"},
		{"wip-encryption", func(data []byte) { data[513] = 0x10 }, source.ErrUnsupported, "WIP"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			data := append([]byte(nil), base...)
			testCase.mutate(data)
			_, err := Open(source.NewMemorySource(1, data), DefaultLimits())
			if !errors.Is(err, testCase.kind) {
				t.Fatalf("error = %v, want kind %v", err, testCase.kind)
			}
			if !strings.Contains(err.Error(), testCase.needle) {
				t.Fatalf("error %q does not contain %q", err, testCase.needle)
			}
		})
	}

	if _, err := Open(source.NewMemorySource(1, base[:100]), DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short source error = %v", err)
	}
	if _, err := Open(source.NewMemorySource(1, base[:600]), DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("truncated source error = %v", err)
	}
}

func TestNBTPageCycle(t *testing.T) {
	fixture := buildMainFixture(FormatUnicode512, CryptNone, false)
	data := fixture.build()
	offset := fixture.nbtOffset
	page := data[offset : offset+512]
	page[488] = 1 // count
	page[489] = 1 // maximum
	page[490] = 24
	page[491] = 1 // branch level
	putU64(page, 0, 0)
	putU64(page, 8, 0x40)            // child BID: the same root
	putU64(page, 16, uint64(offset)) // child offset: this page
	page[496], page[497] = 0x81, 0x81
	putU32(page, 504, 0x40)
	putU32(page, 500, crc32PST(page[:496]))
	_, err := Open(source.NewMemorySource(1, data), DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle error = %v", err)
	}
}

func TestBlockTrailerErrorsAndCRCWarning(t *testing.T) {
	fixture := buildMainFixture(FormatUnicode512, CryptNone, false)
	block := fixture.blocks[0]
	geometry := blockGeometryForFormat(fixture.format)
	alloc, err := geometry.allocation(int(block.cb))
	if err != nil {
		t.Fatalf("allocation: %v", err)
	}
	trailer := int(block.ib) + alloc - geometry.footer

	// A bad signature refuses the block when it is first decoded.
	data := fixture.build()
	data[trailer+2] ^= 0xFF
	reader, err := Open(source.NewMemorySource(1, data), DefaultLimits())
	if err != nil {
		t.Fatalf("Open decoded a data block during the tree walk: %v", err)
	}
	if _, err := reader.Folders(); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("bad signature error = %v", err)
	}

	// A bad CRC is a warning; the bytes are still returned.
	data = fixture.build()
	data[trailer+4] ^= 0xFF
	reader = openData(t, data)
	if _, err := reader.Folders(); err != nil {
		t.Fatalf("Folders with a bad CRC: %v", err)
	}
	if reader.Stats().ChecksumMismatches == 0 {
		t.Fatal("CRC mismatch was not counted")
	}
}

func TestLimits(t *testing.T) {
	data := buildMainFixture(FormatUnicode512, CryptNone, false).build()
	_, err := Open(source.NewMemorySource(1, data), Limits{MaxNodes: 1})
	if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("limit error = %v", err)
	}
}

func TestRTFDecompression(t *testing.T) {
	decoded, err := DecompressRTF(referenceRTFStream(), 64*1024)
	if err != nil {
		t.Fatalf("DecompressRTF: %v", err)
	}
	if string(decoded.Markup) != referenceRTFMarkup {
		t.Fatalf("markup = %q", decoded.Markup)
	}
	if decoded.Truncated || decoded.CRCMismatch {
		t.Fatalf("decoded flags = %+v", decoded)
	}

	limited, err := DecompressRTF(referenceRTFStream(), 16)
	if err != nil {
		t.Fatalf("limited DecompressRTF: %v", err)
	}
	if !limited.Truncated || string(limited.Markup) != referenceRTFMarkup[:16] {
		t.Fatalf("limited markup = %q truncated=%v", limited.Markup, limited.Truncated)
	}

	if _, err := DecompressRTF(referenceRTFStream()[:4], 1024); err == nil {
		t.Fatal("a short RTF header was accepted")
	}
	unknown := append([]byte(nil), referenceRTFStream()...)
	copy(unknown[8:12], []byte("XXXX"))
	if _, err := DecompressRTF(unknown, 1024); err == nil {
		t.Fatal("an unknown RTF compression type was accepted")
	}

	// MELA is stored, not compressed.
	markup := []byte("{\\rtf1 stored}")
	mela := make([]byte, 16)
	putU32(mela, 0, uint32(len(markup)+12))
	putU32(mela, 4, uint32(len(markup)))
	copy(mela[8:12], rtfMagicMELA[:])
	mela = append(mela, markup...)
	stored, err := DecompressRTF(mela, 1024)
	if err != nil || string(stored.Markup) != string(markup) || stored.CRCMismatch {
		t.Fatalf("MELA decode = %+v err=%v", stored, err)
	}

	// A stream without an end marker is a refusal.
	tokens := append([]byte{0x00}, []byte("abcdefgh")...)
	stream := make([]byte, 16)
	putU32(stream, 0, uint32(len(tokens)+12))
	putU32(stream, 4, 8)
	copy(stream[8:12], rtfMagicLZFu[:])
	putU32(stream, 12, crc32PST(tokens))
	stream = append(stream, tokens...)
	if _, err := DecompressRTF(stream, 1024); err == nil || !strings.Contains(err.Error(), "end marker") {
		t.Fatalf("end-marker error = %v", err)
	}

	// A decoded length that disagrees with the header is a refusal.
	mismatched := append([]byte(nil), referenceRTFStream()...)
	putU32(mismatched, 4, leU32(mismatched, 4)+1)
	if _, err := DecompressRTF(mismatched, 64*1024); err == nil {
		t.Fatal("a mismatched decoded length was accepted")
	}
}

func TestCryptPrimitives(t *testing.T) {
	seen := make(map[byte]bool)
	for value := 0; value < 256; value++ {
		seen[mpbbCrypt[value]] = true
	}
	if len(seen) != 256 {
		t.Fatal("mpbbR is not a permutation")
	}
	for value := 0; value < 256; value++ {
		once := mpbbCrypt[256+value]
		if mpbbCrypt[256+int(once)] != byte(value) {
			t.Fatalf("mpbbS is not an involution at %d", value)
		}
		forward := mpbbCrypt[value]
		if mpbbCrypt[512+int(forward)] != byte(value) {
			t.Fatalf("mpbbI is not the inverse of mpbbR at %d", value)
		}
	}
	data := make([]byte, 1000)
	for index := range data {
		data[index] = byte(index)
	}
	original := append([]byte(nil), data...)
	permute(data, true)
	permute(data, false)
	if string(data) != string(original) {
		t.Fatal("permute is not reversible")
	}
	cyclic(data, 0x20)
	cyclic(data, 0x20)
	if string(data) != string(original) {
		t.Fatal("cyclic is not its own inverse")
	}
	if crc32PST(nil) != 0 || crc32PST([]byte("123456789")) != 0x2DFD2D88 {
		t.Fatal("CRC-32 vectors do not match")
	}
	if crc32PST([]byte("!BDN")) != 0x6EE17763 {
		t.Fatal("the PST signature CRC does not match")
	}
	if blockSignature(0x1000, 0x42) != 0x1042 {
		t.Fatal("block signature fold is wrong")
	}
}

func TestSiblingNID(t *testing.T) {
	if siblingNID(0x8043, 0x07) != 0x8047 {
		t.Fatal("criteria sibling NID")
	}
	if siblingNID(0x8043, 0x10) != 0x8050 {
		t.Fatal("contents sibling NID")
	}
	if siblingNID(0x8047, 0x07) != 0x8047 {
		t.Fatal("a NID already of the requested type must not change")
	}
}

func TestFiletimeConversion(t *testing.T) {
	if !Filetime(0).Time().IsZero() {
		t.Fatal("zero FILETIME must not become 1601")
	}
	time := Filetime(132000000000000000).Time()
	if time.IsZero() || time.Year() < 2000 {
		t.Fatalf("FILETIME converted to %v", time)
	}
}
