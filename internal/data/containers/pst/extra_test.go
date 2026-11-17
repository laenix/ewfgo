package pst

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func buildEmbeddedFixture() *fixtureBuilder {
	f := newFixture(FormatUnicode512, CryptNone)
	messagePC := f.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Parent"),
	}), true)

	// PidTagAttachDataObject is an eight-byte reference whose first four
	// bytes name the embedded message NID.
	objectReference := make([]byte, 8)
	putU32(objectReference, 0, 0x3004)
	objectReferenceBlock := f.addBlock(objectReference, true)
	embeddedPC := f.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Embedded subject"),
		pText(FormatUnicode512, propSenderName, "Eve"),
		pText(FormatUnicode512, propSenderSMTPAddress, "eve@example.com"),
		pText(FormatUnicode512, propMessageClass, "IPM.Note"),
		pTime(propClientSubmitTime, Filetime(132000000000000010)),
		pI4(propMessageSize, 99),
		pText(FormatUnicode512, propInternetMessageID, "<embedded@example>"),
	}), true)
	objectNested := f.addBlock(slblock(FormatUnicode512, []slEntry{
		{subnode: 0x03FF, data: objectReferenceBlock.bid},
		{subnode: 0x3004, data: embeddedPC.bid},
	}), true)
	objectPC := f.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propAttachLongFilename, "embedded.msg"),
		pI4(propAttachMethod, 5),
		pSubnode(propAttachData, 0x000D, 0x03FF),
	}), true)

	row := make([]byte, 25)
	putU32(row, 0, 0x2001)
	putU32(row, 4, 0)
	putU32(row, 8, 5)
	putU32(row, 12, 0)
	putU64(row, 16, uint64(Filetime(132000000000000004)))
	row[24] = 0xF8
	table := f.addBlock(buildHeapBlock(tcClient, hidFor(0), [][]byte{
		tcInfoBlock([]tcColSpec{
			{tag: tag(propLTPRowID, 0x0003), offset: 0, width: 4, bit: 0},
			{tag: tag(propAttachFilename, 0x001F), offset: 4, width: 4, bit: 1},
			{tag: tag(propAttachMethod, 0x0003), offset: 8, width: 4, bit: 2},
			{tag: tag(propAttachSize, 0x0003), offset: 12, width: 4, bit: 3},
			{tag: tag(propAttachCreationTime, 0x0040), offset: 16, width: 8, bit: 4},
		}, [4]uint16{24, 24, 24, 25}, hidFor(1)),
		row,
	}), true)

	messageTree := f.addBlock(slblock(FormatUnicode512, []slEntry{
		{subnode: AttachmentTableNID, data: table.bid},
		{subnode: 0x2001, data: objectPC.bid, nested: objectNested.bid},
	}), true)
	f.nbt = []Node{{NID: 0x1004, Data: messagePC.bid, Subnode: messageTree.bid, Parent: 0x42}}
	return f
}

func buildSearchFixture() *fixtureBuilder {
	f := newFixture(FormatUnicode512, CryptNone)
	rootPC := f.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propDisplayName, "Root"),
	}), true)
	criteriaPC := f.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propDisplayName, "Search"),
		pI4(propFolderType, 3),
		pI4(propSearchFolderTemplateID, 7),
		pBinary(propSearchFolderID, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
		pBinary(propSearchFolderDefinition, []byte{9, 9, 9}),
		pI4(propSearchFolderStorageType, 1),
		pI4(propSearchFolderTag, 0x22),
		pI4(propSearchFolderEFPFlags, 4),
		pTime(propSearchFolderLastUsed, Filetime(132000000000000020)),
	}), true)
	row := make([]byte, 9)
	putU32(row, 0, 0x1004)
	putU32(row, 4, 0x42)
	row[8] = 0x80
	table := f.addBlock(buildHeapBlock(tcClient, hidFor(0), [][]byte{
		tcInfoBlock([]tcColSpec{
			{tag: tag(propLTPParentNID, 0x0003), offset: 4, width: 4, bit: 0},
		}, [4]uint16{8, 8, 8, 9}, hidFor(1)),
		row,
	}), true)
	f.nbt = []Node{
		{NID: 0x22, Data: rootPC.bid, Parent: 0x22},
		{NID: 0x8043, Data: criteriaPC.bid, Parent: 0x22},
		{NID: 0x8047, Data: criteriaPC.bid, Parent: 0x8043},
		{NID: 0x8050, Data: table.bid, Parent: 0x8043},
	}
	return f
}

func inlineI2(value int16) []byte {
	out := make([]byte, 2)
	putU16(out, 0, uint16(value))
	return out
}

func inlineU32(value uint32) []byte {
	out := make([]byte, 4)
	putU32(out, 0, value)
	return out
}

func u64Value(value uint64) []byte {
	out := make([]byte, 8)
	putU64(out, 0, value)
	return out
}

func buildAllTypesFixture() *fixtureBuilder {
	f := newFixture(FormatAnsi, CryptNone)
	clsid := make([]byte, 16)
	for index := range clsid {
		clsid[index] = byte(index)
	}
	properties := []propSpec{
		{id: 0x1001, kind: 0x0001},
		{id: 0x1002, kind: 0x0002, inline: inlineI2(-2)},
		pI4(0x1003, 123456),
		{id: 0x1004, kind: 0x0004, inline: inlineU32(math.Float32bits(1.5))},
		{id: 0x1005, kind: 0x0005, value: u64Value(math.Float64bits(2.5))},
		{id: 0x1006, kind: 0x0006, value: u64Value(0x1122334455667788)},
		{id: 0x1007, kind: 0x0007, value: u64Value(math.Float64bits(3.25))},
		{id: 0x100A, kind: 0x000A, inline: inlineU32(7)},
		pBool(0x100B, true),
		{id: 0x1014, kind: 0x0014, value: u64Value(0x0102030405060708)},
		{id: 0x101E, kind: 0x001E, value: []byte{'A', 0x80, 'B', 0}},
		{id: 0x101F, kind: 0x001F, value: utf16z("Hello")},
		pTime(0x1040, Filetime(132000000000000030)),
		{id: 0x100D, kind: 0x000D, value: []byte{1, 2, 3}},
		{id: 0x1048, kind: 0x0048, value: clsid},
		{id: 0x1102, kind: 0x0102, value: []byte{9, 8, 7}},
		{id: 0x111E, kind: 0x101E, value: multiValue([][]byte{latin1z("one"), latin1z("two")})},
		{id: 0x111F, kind: 0x101F, value: multiValue([][]byte{utf16z("a"), utf16z("b")})},
		{id: 0x1444, kind: 0x4444, value: []byte{1, 2, 3, 4}},
		pI4(propMessageCodepage, 1252),
	}
	pc := f.addBlock(pcBlock(properties), true)
	f.nbt = []Node{{NID: 0x1004, Data: pc.bid, Parent: 0x42}}
	return f
}

func propertyByID(t *testing.T, properties []Property, id uint16) *Property {
	t.Helper()
	for index := range properties {
		if properties[index].ID == id {
			return &properties[index]
		}
	}
	t.Fatalf("property 0x%04X is absent", id)
	return nil
}

func TestEmbeddedAttachment(t *testing.T) {
	reader := openData(t, buildEmbeddedFixture().build())
	attachments, present, err := reader.Attachments(0x1004)
	if err != nil || !present || len(attachments) != 1 {
		t.Fatalf("Attachments present=%v err=%v", present, err)
	}
	attachment := attachments[0]
	requireText(t, attachment.Filename, "embedded.msg", "filename")
	if attachment.Method == nil || *attachment.Method != 5 {
		t.Fatalf("method = %v", attachment.Method)
	}
	if attachment.DataBytes != nil || attachment.SHA256 != nil {
		t.Fatalf("an embedded message has no file bytes: bytes=%v sha=%v", attachment.DataBytes, attachment.SHA256)
	}
	if attachment.DataProblem != nil {
		t.Fatalf("data problem = %q", *attachment.DataProblem)
	}
	if attachment.Created == nil || *attachment.Created != Filetime(132000000000000004) {
		t.Fatalf("cell FILETIME = %v", attachment.Created)
	}
	embedded := attachment.Embedded
	if embedded == nil {
		t.Fatal("embedded message is absent")
	}
	if embedded.NID != 0x3004 {
		t.Fatalf("embedded NID = %#x", embedded.NID)
	}
	requireText(t, embedded.Subject, "Embedded subject", "embedded subject")
	requireText(t, embedded.SenderName, "Eve", "embedded sender")
	requireText(t, embedded.SenderEmail, "eve@example.com", "embedded sender email")
	if embedded.SenderEmailSource != "smtp-address" {
		t.Fatalf("embedded sender source = %q", embedded.SenderEmailSource)
	}
	requireText(t, embedded.MessageClass, "IPM.Note", "embedded class")
	if embedded.Size == nil || *embedded.Size != 99 {
		t.Fatalf("embedded size = %v", embedded.Size)
	}
	if embedded.SubmitTime == nil || *embedded.SubmitTime != Filetime(132000000000000010) {
		t.Fatalf("embedded submit time = %v", embedded.SubmitTime)
	}
	requireText(t, embedded.MessageID, "<embedded@example>", "embedded message id")
}

func TestSearchFolder(t *testing.T) {
	reader := openData(t, buildSearchFixture().build())
	folders, err := reader.SearchFolders()
	if err != nil {
		t.Fatalf("SearchFolders: %v", err)
	}
	if len(folders) != 1 {
		t.Fatalf("search folders = %d, want 1", len(folders))
	}
	folder := folders[0]
	if folder.NID != 0x8043 {
		t.Fatalf("search folder NID = %#x", folder.NID)
	}
	requireText(t, folder.Name, "Search", "search folder name")
	if folder.FolderType == nil || *folder.FolderType != 3 {
		t.Fatalf("folder type = %v", folder.FolderType)
	}
	if folder.TemplateID == nil || *folder.TemplateID != 7 {
		t.Fatalf("template id = %v", folder.TemplateID)
	}
	if folder.StorageType == nil || *folder.StorageType != 1 {
		t.Fatalf("storage type = %v", folder.StorageType)
	}
	if folder.Tag == nil || *folder.Tag != 0x22 {
		t.Fatalf("tag = %v", folder.Tag)
	}
	if folder.EFPFlags == nil || *folder.EFPFlags != 4 {
		t.Fatalf("efp flags = %v", folder.EFPFlags)
	}
	if len(folder.FolderID) != 16 || len(folder.Definition) != 3 {
		t.Fatalf("folder id/definition lengths = %d/%d", len(folder.FolderID), len(folder.Definition))
	}
	if folder.LastUsed == nil || *folder.LastUsed != Filetime(132000000000000020) {
		t.Fatalf("last used = %v", folder.LastUsed)
	}
	if folder.CriteriaProblem != nil || folder.TableProblem != nil {
		t.Fatalf("search problems = %v / %v", folder.CriteriaProblem, folder.TableProblem)
	}
	if len(folder.Links) != 1 {
		t.Fatalf("links = %d, want 1", len(folder.Links))
	}
	link := folder.Links[0]
	if link.MessageNID != 0x1004 {
		t.Fatalf("link message NID = %#x", link.MessageNID)
	}
	if link.ParentNID == nil || *link.ParentNID != 0x42 {
		t.Fatalf("link parent NID = %v", link.ParentNID)
	}
	if link.Problem != nil {
		t.Fatalf("link problem = %q", *link.Problem)
	}
}

func TestAllPropertyTypes(t *testing.T) {
	reader := openData(t, buildAllTypesFixture().build())
	properties, err := reader.Properties(0x1004)
	if err != nil {
		t.Fatalf("Properties: %v", err)
	}
	if value := propertyByID(t, properties, 0x1001); value.Value.Kind != ValueNull {
		t.Fatalf("null = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1002); value.Value.Kind != ValueI2 || value.Value.I2 != -2 {
		t.Fatalf("i2 = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1003); value.Value.Kind != ValueI4 || value.Value.I4 != 123456 {
		t.Fatalf("i4 = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1004); value.Value.Kind != ValueFloat || value.Value.Float != 1.5 {
		t.Fatalf("float = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1005); value.Value.Kind != ValueDouble || value.Value.Double != 2.5 {
		t.Fatalf("double = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1006); value.Value.Kind != ValueCurrency || value.Value.Currency != 0x1122334455667788 {
		t.Fatalf("currency = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1007); value.Value.Kind != ValueAppTime || value.Value.AppTime != 3.25 {
		t.Fatalf("app time = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x100A); value.Value.Kind != ValueError || value.Value.Error != 7 {
		t.Fatalf("error = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x100B); value.Value.Kind != ValueBoolean || !value.Value.Boolean {
		t.Fatalf("boolean = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1014); value.Value.Kind != ValueI8 || value.Value.I8 != 0x0102030405060708 {
		t.Fatalf("i8 = %+v", value.Value)
	}
	string8 := propertyByID(t, properties, 0x101E)
	if string8.Value.Kind != ValueString || string8.Value.String != "A€B" {
		t.Fatalf("string8 = %+v", string8.Value)
	}
	if string8.TextBasis == nil || string8.TextBasis.BytesPreserved || string8.TextBasis.CodePage != 1252 {
		t.Fatalf("string8 basis = %+v", string8.TextBasis)
	}
	if value := propertyByID(t, properties, 0x101F); value.Value.Kind != ValueString || value.Value.String != "Hello" {
		t.Fatalf("unicode string = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1040); value.Value.Kind != ValueTime || value.Value.Time != Filetime(132000000000000030) {
		t.Fatalf("time = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x100D); value.Value.Kind != ValueObject || string(value.Value.Object) != string([]byte{1, 2, 3}) {
		t.Fatalf("object = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1048); value.Value.Kind != ValueCLSID || value.Value.CLSID[15] != 15 {
		t.Fatalf("clsid = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1102); value.Value.Kind != ValueBinary || string(value.Value.Binary) != string([]byte{9, 8, 7}) {
		t.Fatalf("binary = %+v", value.Value)
	}
	multi8 := propertyByID(t, properties, 0x111E)
	if multi8.Value.Kind != ValueMultiString || len(multi8.Value.MultiString) != 2 || multi8.Value.MultiString[0] != "one" {
		t.Fatalf("multi string8 = %+v", multi8.Value)
	}
	if multi8.TextBasis == nil || multi8.TextBasis.CodePage != 1252 {
		t.Fatalf("multi string8 basis = %+v", multi8.TextBasis)
	}
	if value := propertyByID(t, properties, 0x111F); value.Value.Kind != ValueMultiString || value.Value.MultiString[1] != "b" {
		t.Fatalf("multi unicode = %+v", value.Value)
	}
	if value := propertyByID(t, properties, 0x1444); value.Value.Kind != ValueUnsupported || value.Value.UnsupportedKind != 0x4444 || value.Value.UnsupportedLen != 4 {
		t.Fatalf("unsupported = %+v", value.Value)
	}
}

func TestOrphanRecovery(t *testing.T) {
	fixture := buildMainFixture(FormatUnicode512, CryptNone, false)
	deletedPC := fixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Deleted"),
		pText(FormatUnicode512, propMessageClass, "IPM.Note"),
		pText(FormatUnicode512, propBody, "gone"),
		pBinary(propHTML, []byte("<html>gone</html>")),
		pI4(propMessageSize, 42),
	}), true)
	fixture.nbt = append(fixture.nbt, Node{NID: 0x2004, Data: deletedPC.bid, Parent: 0x999})
	reader := openData(t, fixture.build())

	messages, err := reader.Messages()
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	for _, message := range messages {
		if message.NID == 0x2004 {
			t.Fatal("an orphaned message was returned as an allocated message")
		}
	}

	recovery, err := reader.RecoverDeleted()
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}
	if len(recovery.Messages) != 1 {
		t.Fatalf("recovered messages = %d, want 1", len(recovery.Messages))
	}
	item := recovery.Messages[0]
	if item.NID == nil || *item.NID != 0x2004 {
		t.Fatalf("recovered NID = %v", item.NID)
	}
	if item.Recovery != RecoveryOrphanNode || item.Recovery.Label() != "orphaned-node" {
		t.Fatalf("recovery kind = %v", item.Recovery)
	}
	if item.Parent == nil || *item.Parent != 0x999 {
		t.Fatalf("recovered parent = %v", item.Parent)
	}
	if item.ParentName != nil {
		t.Fatalf("recovered parent name = %q", *item.ParentName)
	}
	requireText(t, item.Subject, "Deleted", "recovered subject")
	if !item.BodyStream || item.BodyBytes == nil || *item.BodyBytes == 0 {
		t.Fatalf("recovered body = stream %v bytes %v", item.BodyStream, item.BodyBytes)
	}
	if item.HTMLBytes == nil || *item.HTMLBytes == 0 {
		t.Fatalf("recovered html bytes = %v", item.HTMLBytes)
	}
	if item.AttachmentCount == nil || *item.AttachmentCount != 0 {
		t.Fatalf("recovered attachment count = %v", item.AttachmentCount)
	}
	if item.Size == nil || *item.Size != 42 {
		t.Fatalf("recovered size = %v", item.Size)
	}
	if len(recovery.Refusals) != 0 || len(recovery.Problems) != 0 {
		t.Fatalf("recovery refusals/problems = %+v", recovery)
	}
}

func TestEntryParsersAndLabels(t *testing.T) {
	ansi := make([]byte, 12)
	putU32(ansi, 4, 0x104)
	putU32(ansi, 8, 0x200)
	if bid, ib := nbtBranchEntry(ansi, true); bid != 0x104 || ib != 0x200 {
		t.Fatalf("ANSI NBT branch = %#x/%#x", bid, ib)
	}
	if bid, ib := bbtBranchEntry(ansi, true); bid != 0x104 || ib != 0x200 {
		t.Fatalf("ANSI BBT branch = %#x/%#x", bid, ib)
	}
	unicode := make([]byte, 24)
	putU64(unicode, 8, 0x104)
	putU64(unicode, 16, 0x200)
	if bid, ib := nbtBranchEntry(unicode, false); bid != 0x104 || ib != 0x200 {
		t.Fatalf("Unicode NBT branch = %#x/%#x", bid, ib)
	}
	if bid, ib := bbtBranchEntry(unicode, false); bid != 0x104 || ib != 0x200 {
		t.Fatalf("Unicode BBT branch = %#x/%#x", bid, ib)
	}
	indexANSI := make([]byte, 8)
	putU32(indexANSI, 4, 0x88)
	if got := subnodeLayoutForFormat(FormatAnsi).index(indexANSI, 0); got != 0x88 {
		t.Fatalf("ANSI subnode index = %#x", got)
	}
	indexUnicode := make([]byte, 16)
	putU64(indexUnicode, 8, 0x99)
	if got := subnodeLayoutForFormat(FormatUnicode512).index(indexUnicode, 0); got != 0x99 {
		t.Fatalf("Unicode subnode index = %#x", got)
	}

	if LooksLike([]byte("!BDN\x00\x00\x00\x00SM")) == false {
		t.Fatal("LooksLike rejected a PST")
	}
	if newFixture(FormatAnsi, CryptNone).format.Label() != "ansi" ||
		FormatUnicode512.Label() != "unicode-512" ||
		FormatUnicode4K.Label() != "unicode-4k" ||
		FormatUnicode512.String() != "unicode-512" {
		t.Fatal("format labels")
	}
	if StorePersonal.Label() != "pst" || StoreOffline.String() != "ost" {
		t.Fatal("store kind labels")
	}
	if CryptNone.Label() != "none" || CryptPermute.String() != "permute" || CryptCyclic.Label() != "cyclic" {
		t.Fatal("crypt labels")
	}
	if FormatAnsi.PageBytes() != 512 || !FormatAnsi.IsAnsi() || FormatUnicode4K.PageBytes() != 4096 || FormatUnicode4K.IsAnsi() {
		t.Fatal("format geometry")
	}
	kinds := []ValueKind{ValueNull, ValueBoolean, ValueI2, ValueI4, ValueI8, ValueFloat,
		ValueDouble, ValueCurrency, ValueAppTime, ValueError, ValueTime, ValueCLSID,
		ValueString, ValueMultiString, ValueBinary, ValueObject, ValueUnsupported}
	for _, kind := range kinds {
		if kind.Label() == "" {
			t.Fatalf("value kind %d has no label", kind)
		}
	}
	for _, kind := range []RecoveryKind{RecoveryFreeNode, RecoveryOrphanNode, RecoveryOrphanBlock, RecoveryFreeBlock} {
		if kind.Label() == "" {
			t.Fatal("recovery kind has no label")
		}
	}
	if MapAMap.Label() != "amap" || MapPMap.String() != "pmap" {
		t.Fatal("allocation labels")
	}
	if (Header{CryptMethod: CryptPermute}).CryptLabel() != "permute" {
		t.Fatal("header crypt label")
	}
}

func TestPropertyParsingErrors(t *testing.T) {
	text := textContext{ansi: true}
	cases := []struct {
		name  string
		id    uint16
		kind  uint16
		value []byte
	}{
		{"i2-width", 1, 0x0002, []byte{1}},
		{"i4-width", 1, 0x0003, []byte{1, 2}},
		{"i8-width", 1, 0x0014, []byte{1}},
		{"time-width", 1, 0x0040, []byte{1}},
		{"boolean-three", 1, 0x000B, []byte{1, 2, 3}},
		{"unicode-odd", 1, 0x001F, []byte{1}},
		{"clsid-width", 1, 0x0048, make([]byte, 15)},
	}
	for _, testCase := range cases {
		if _, err := parseProperty(testCase.id, testCase.kind, testCase.value, text, 100); err == nil {
			t.Fatalf("%s was accepted", testCase.name)
		}
	}
	if property, err := parseProperty(1, 0x000B, []byte{1}, text, 100); err != nil || !property.Value.Boolean {
		t.Fatalf("one-byte boolean = %+v err=%v", property.Value, err)
	}

	if _, err := multiValueSlices(1, nil, 100); err == nil {
		t.Fatal("a short multi-value record was accepted")
	}
	if _, err := multiValueSlices(1, []byte{5, 0, 0, 0}, 2); err == nil {
		t.Fatal("an over-cap multi-value count was accepted")
	}
	if _, err := multiValueSlices(1, []byte{1, 0, 0, 0, 3, 0, 0, 0}, 100); err == nil {
		t.Fatal("an out-of-range multi-value offset was accepted")
	}
	backwards := []byte{2, 0, 0, 0, 12, 0, 0, 0, 8, 0, 0, 0, 1, 2, 3, 4}
	if _, err := multiValueSlices(1, backwards, 100); err == nil {
		t.Fatal("backwards multi-value offsets were accepted")
	}
	if _, err := multiString16(1, []byte{1, 0, 0, 0, 8, 0, 0, 0, 1}, 100); err == nil {
		t.Fatal("an odd multi-value UTF-16 item was accepted")
	}

	contexts := []struct {
		context textContext
		input   []byte
		want    string
		basis   TextBasis
	}{
		{textContext{ansi: true, codepage: 65001, hasCodepage: true}, []byte("hi\x00"), "hi", TextBasis{CodePage: 65001}},
		{textContext{ansi: true, codepage: 20127, hasCodepage: true}, []byte("hi"), "hi", TextBasis{CodePage: 20127}},
		{textContext{ansi: true, codepage: 28591, hasCodepage: true}, []byte{0xE9}, "é", TextBasis{CodePage: 28591}},
		{textContext{ansi: true, codepage: 1252, hasCodepage: true}, []byte{0x80}, "€", TextBasis{CodePage: 1252}},
		{textContext{ansi: true, codepage: 9999, hasCodepage: true}, []byte{0x41}, "A", TextBasis{BytesPreserved: true}},
		{textContext{ansi: false, codepage: 1252, hasCodepage: true}, []byte{0x80}, "\u0080", TextBasis{BytesPreserved: true}},
	}
	for index, testCase := range contexts {
		got, basis := testCase.context.decode(testCase.input)
		if got != testCase.want || basis != testCase.basis {
			t.Fatalf("context %d = %q %+v, want %q %+v", index, got, basis, testCase.want, testCase.basis)
		}
	}
	if got, ok := decodeCodePage(65001, []byte{0xFF}); ok {
		t.Fatalf("invalid UTF-8 decoded to %q", got)
	}
	if _, ok := decodeCodePage(20127, []byte{0x80}); ok {
		t.Fatal("ASCII accepted a high byte")
	}
	if _, ok := decodeWindows1252([]byte{0x81}); ok {
		t.Fatal("Windows-1252 accepted an unassigned position")
	}
	if got := latin1([]byte{'a', 0xE9, 0}); got != "aé" {
		t.Fatalf("latin1 = %q", got)
	}
	if got := utf16le(utf16z("Hi")); got != "Hi" {
		t.Fatalf("utf16le = %q", got)
	}

	unsupported, err := parseProperty(1, 0x4444, []byte{1, 2, 3}, text, 100)
	if err != nil || unsupported.Value.Kind != ValueUnsupported || unsupported.Value.UnsupportedLen != 3 {
		t.Fatalf("unsupported = %+v err=%v", unsupported.Value, err)
	}
}

func TestTableAndHeapErrors(t *testing.T) {
	layout := hidLayoutForPageBytes(512)
	columns := []tcColSpec{{tag: tag(0x3001, 0x001F), offset: 8, width: 4, bit: 2}}
	short := [][]byte{buildHeapBlock(tcClient, hidFor(0), [][]byte{make([]byte, tcInfoBytes-1)})}
	if _, err := readTableContext(short, layout); err == nil || !strings.Contains(err.Error(), "shorter") {
		t.Fatalf("short TCINFO error = %v", err)
	}

	backwards := [][]byte{buildHeapBlock(tcClient, hidFor(0), [][]byte{
		tcInfoBlock(columns, [4]uint16{12, 8, 12, 13}, 0),
	})}
	if _, err := readTableContext(backwards, layout); err == nil || !strings.Contains(err.Error(), "go backwards") {
		t.Fatalf("backwards groups error = %v", err)
	}

	pastCEBColumns := []tcColSpec{{tag: tag(0x3001, 0x001F), offset: 10, width: 4, bit: 0}}
	pastCEB := [][]byte{buildHeapBlock(tcClient, hidFor(0), [][]byte{
		tcInfoBlock(pastCEBColumns, [4]uint16{12, 12, 12, 13}, 0),
	})}
	if _, err := readTableContext(pastCEB, layout); err == nil || !strings.Contains(err.Error(), "cell bitmap") {
		t.Fatalf("column past bitmap error = %v", err)
	}

	// A variable column whose HNID slot is two bytes must be refused when a
	// row with that cell is parsed.
	shortHNIDColumns := []tcColSpec{
		{tag: tag(propLTPRowID, 0x0003), offset: 0, width: 4, bit: 0},
		{tag: tag(0x3001, 0x001F), offset: 4, width: 2, bit: 1},
	}
	row := make([]byte, 7)
	row[6] = 0xC0
	shortHNID := [][]byte{buildHeapBlock(tcClient, hidFor(0), [][]byte{
		tcInfoBlock(shortHNIDColumns, [4]uint16{6, 6, 6, 7}, 0),
	})}
	context, err := readTableContext(shortHNID, layout)
	if err != nil {
		t.Fatalf("short HNID table header: %v", err)
	}
	if _, err := context.rowsIn([][]byte{row}, 100, 1<<20); err == nil || !strings.Contains(err.Error(), "2-byte HNID") {
		t.Fatalf("short HNID error = %v", err)
	}

	if _, err := readTableContext([][]byte{buildHeapBlock(pcClient, hidFor(0), [][]byte{{0x7C}})}, layout); err == nil {
		t.Fatal("a PC heap was accepted as a table")
	}
	if _, err := readPC([][]byte{buildHeapBlock(tcClient, hidFor(0), [][]byte{{0xB5}})}, layout, 100); err == nil {
		t.Fatal("a TC heap was accepted as a property context")
	}

	if _, err := parseHeap(nil, layout); err == nil {
		t.Fatal("an empty heap was accepted")
	}
	badSignature := buildHeapBlock(tcClient, hidFor(0), [][]byte{{0}})
	badSignature[2] = 0
	if _, err := parseHeap([][]byte{badSignature}, layout); err == nil {
		t.Fatal("a bad heap signature was accepted")
	}
	backwardsMap := buildHeapBlock(tcClient, hidFor(0), [][]byte{{1}, {2}})
	ib := int(leU16(backwardsMap, 0))
	putU16(backwardsMap, ib+6, 1)
	if _, err := parseHeap([][]byte{backwardsMap}, layout); err == nil {
		t.Fatal("backwards heap allocation offsets were accepted")
	}

	heap, err := parseHeap([][]byte{buildHeapBlock(tcClient, hidFor(0), [][]byte{{1}})}, layout)
	if err != nil {
		t.Fatalf("parseHeap: %v", err)
	}
	if _, err := heap.allocation(0); err == nil {
		t.Fatal("HID 0 was accepted")
	}
	if _, err := heap.allocation((9 << 16) | 0x20); err == nil {
		t.Fatal("an out-of-range heap block was accepted")
	}

	// BTH errors.
	badBTH := func(header, records []byte) [][]byte {
		return [][]byte{buildHeapBlock(pcClient, hidFor(0), [][]byte{header, records})}
	}
	header := make([]byte, 8)
	header[0] = bthType
	header[1] = 2
	header[2] = 6
	header[3] = 9
	putU32(header, 4, hidFor(1))
	if _, err := readPC(badBTH(header, nil), layout, 100); err == nil {
		t.Fatal("a BTH with nine levels was accepted")
	}
	header[3] = 0
	header[2] = 7
	if _, err := readPC(badBTH(header, nil), layout, 100); err == nil {
		t.Fatal("a BTH with a seven-byte value was accepted")
	}
	header[2] = 6
	badRecord := make([]byte, 8)
	putU16(badRecord, 0, 0x3001)
	putU16(badRecord, 2, 0x001F)
	putU32(badRecord, 4, 0x0004) // low five bits 4, neither HID nor subnode
	if _, err := readPC(badBTH(header, badRecord), layout, 100); err == nil {
		t.Fatal("a property naming a non-HID, non-subnode value was accepted")
	}
	putU32(badRecord, 4, 0) // a zero HID means the property is absent
	properties, err := readPC(badBTH(header, badRecord), layout, 100)
	if err != nil || len(properties) != 0 {
		t.Fatalf("zero HID property = %+v err=%v", properties, err)
	}
	if _, err := readPC(badBTH(header, make([]byte, 7)), layout, 100); err == nil {
		t.Fatal("a BTH level that does not divide into records was accepted")
	}
}

func TestPublicAccessors(t *testing.T) {
	reader := openData(t, buildMainFixture(FormatUnicode512, CryptNone, false).build())
	if len(reader.Nodes()) != 5 {
		t.Fatalf("Nodes() = %d", len(reader.Nodes()))
	}
	if len(reader.FreeNodes()) != 0 {
		t.Fatalf("FreeNodes() = %d", len(reader.FreeNodes()))
	}
	node, ok := reader.Node(0x1004)
	if !ok || node.NID != 0x1004 || !node.IsMessage() || node.IsFolder() || node.IsAssociatedMessage() {
		t.Fatalf("Node(0x1004) = %+v ok=%v", node, ok)
	}
	if _, ok := reader.Node(0x7777); ok {
		t.Fatal("Node returned a missing NID")
	}
	message, err := reader.Message(0x1004)
	if err != nil {
		t.Fatalf("Message: %v", err)
	}
	requireText(t, message.Subject, "Quarterly numbers", "message subject")
	if _, err := reader.Message(0x42); err == nil {
		t.Fatal("Message accepted a folder node")
	}
	blocks, err := reader.NodeBlocks(0x1004)
	if err != nil || len(blocks) == 0 {
		t.Fatalf("NodeBlocks = %d err=%v", len(blocks), err)
	}
	data, err := reader.NodeData(0x1004)
	if err != nil || len(data) == 0 {
		t.Fatalf("NodeData = %d err=%v", len(data), err)
	}
	if _, err := reader.NodeData(0x7777); err == nil {
		t.Fatal("NodeData accepted a missing NID")
	}
	if reader.BlockCount() != reader.Stats().BlockCount {
		t.Fatalf("BlockCount = %d, Stats = %d", reader.BlockCount(), reader.Stats().BlockCount)
	}
}

func TestBranchPagesAndSubnodeIndex(t *testing.T) {
	fixture := buildMainFixture(FormatUnicode512, CryptNone, false)
	fixture.bbtLeafOffsets = []int{0x3000, 0x3200}
	fixture.nbtLeafOffsets = []int{0x3400, 0x3600}
	messageNode := &fixture.nbt[2]
	leafBID := messageNode.Subnode
	index := fixture.addBlock(slIndexBlock(FormatUnicode512, leafBID), true)
	messageNode.Subnode = index.bid

	reader := openData(t, fixture.build())
	if reader.Stats().NodeCount != 5 {
		t.Fatalf("nodes = %d", reader.Stats().NodeCount)
	}
	if reader.BlockCount() != 15 {
		t.Fatalf("blocks = %d, want 15", reader.BlockCount())
	}
	messages, err := reader.Messages()
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	message := messageByNID(t, messages, 0x1004)
	requireText(t, message.Subject, "Quarterly numbers", "subject")
	attachments, present, err := reader.Attachments(0x1004)
	if err != nil || !present || len(attachments) != 1 {
		t.Fatalf("Attachments present=%v err=%v", present, err)
	}
	if attachments[0].SHA256 == nil || *attachments[0].SHA256 != expectedSHA256("hello") {
		t.Fatalf("attachment sha = %v", attachments[0].SHA256)
	}
	recovery, err := reader.RecoverDeleted()
	if err != nil || len(recovery.Messages) != 0 || len(recovery.Refusals) != 0 || len(recovery.Problems) != 0 {
		t.Fatalf("recovery through branch/index pages = %+v err=%v", recovery, err)
	}
}

func TestTableCells(t *testing.T) {
	reader := openData(t, buildMainFixture(FormatUnicode512, CryptNone, false).build())
	columns := []tcColSpec{
		{tag: tag(0x3001, 0x101F), offset: 4, width: 4, bit: 0},
		{tag: tag(0x3002, 0x0003), offset: 8, width: 4, bit: 1},
		{tag: tag(0x3003, 0x0003), offset: 12, width: 2, bit: 2},
		{tag: tag(0x3004, 0x0040), offset: 14, width: 8, bit: 3},
	}
	blocks := [][]byte{buildHeapBlock(tcClient, hidFor(0), [][]byte{
		tcInfoBlock(columns, [4]uint16{22, 22, 22, 23}, 0),
	})}
	context, err := readTableContext(blocks, hidLayoutForPageBytes(512))
	if err != nil {
		t.Fatalf("readTableContext: %v", err)
	}
	row := tcRow{id: 1, cells: []tcCell{
		{column: 0, value: tcValue{kind: tcValueBytes, bytes: multiValue([][]byte{utf16z("a"), utf16z("b")})}},
		{column: 1, value: tcValue{kind: tcValueBytes, bytes: inlineU32(1)}},
		{column: 2, value: tcValue{kind: tcValueBytes, bytes: inlineI2(7)}},
		{column: 3, value: tcValue{kind: tcValueBytes, bytes: u64Value(uint64(Filetime(5)))}},
	}}
	joined, err := reader.cellText("test", nil, context, &row, 0x3001)
	if err != nil || joined == nil || *joined != "a; b" {
		t.Fatalf("multi-string cell = %v err=%v", joined, err)
	}
	if _, err := reader.cellText("test", nil, context, &row, 0x3002); err == nil {
		t.Fatal("a non-string cell was accepted as text")
	}
	if value, err := reader.cellText("test", nil, context, &row, 0x9999); err != nil || value != nil {
		t.Fatalf("missing column = %v err=%v", value, err)
	}
	emptyRow := tcRow{id: 2}
	if value, err := reader.cellText("test", nil, context, &emptyRow, 0x3001); err != nil || value != nil {
		t.Fatalf("absent cell = %v err=%v", value, err)
	}

	if value, err := reader.cellUnsigned("test", context, &row, 0x3002); err != nil || value == nil || *value != 1 {
		t.Fatalf("unsigned cell = %v err=%v", value, err)
	}
	if value, err := reader.cellUnsigned("test", context, &row, 0x3003); err != nil || value == nil || *value != 7 {
		t.Fatalf("two-byte cell = %v err=%v", value, err)
	}
	oddRow := tcRow{id: 3, cells: []tcCell{{column: 1, value: tcValue{kind: tcValueBytes, bytes: []byte{1, 2, 3}}}}}
	if _, err := reader.cellUnsigned("test", context, &oddRow, 0x3002); err == nil {
		t.Fatal("a three-byte integer cell was accepted")
	}
	subnodeRow := tcRow{id: 4, cells: []tcCell{{column: 1, value: tcValue{kind: tcValueSubnode, subnode: 0x3F}}}}
	if _, err := reader.cellUnsigned("test", context, &subnodeRow, 0x3002); err == nil {
		t.Fatal("a subnode integer cell was accepted")
	}
	if value, err := reader.cellUnsigned("test", context, &emptyRow, 0x3002); err != nil || value != nil {
		t.Fatalf("absent unsigned cell = %v err=%v", value, err)
	}

	if value, err := reader.cellFiletime("test", context, &row, 0x3004); err != nil || value == nil || *value != Filetime(5) {
		t.Fatalf("filetime cell = %v err=%v", value, err)
	}
	shortTime := tcRow{id: 5, cells: []tcCell{{column: 3, value: tcValue{kind: tcValueBytes, bytes: make([]byte, 7)}}}}
	if _, err := reader.cellFiletime("test", context, &shortTime, 0x3004); err == nil {
		t.Fatal("a seven-byte FILETIME was accepted")
	}
	subnodeTimeRow := tcRow{id: 6, cells: []tcCell{{column: 3, value: tcValue{kind: tcValueSubnode, subnode: 0x3F}}}}
	if _, err := reader.cellFiletime("test", context, &subnodeTimeRow, 0x3004); err == nil {
		t.Fatal("a subnode FILETIME was accepted")
	}
	if value, err := reader.cellFiletime("test", context, &emptyRow, 0x3004); err != nil || value != nil {
		t.Fatalf("absent FILETIME = %v err=%v", value, err)
	}
}

func TestPropertyHelpers(t *testing.T) {
	properties := []Property{
		{ID: 1, Value: Value{Kind: ValueString, String: "é"}},
		{ID: 2, Value: Value{Kind: ValueMultiString, MultiString: []string{"a", "b"}}},
		{ID: 3, Value: Value{Kind: ValueBinary, Binary: []byte{1, 2, 3}}},
		{ID: 4, Value: Value{Kind: ValueObject, Object: []byte{1, 2}}},
		{ID: 5, Value: Value{Kind: ValueUnsupported, UnsupportedLen: 9}},
		{ID: 6, Value: Value{Kind: ValueI2, I2: 2}},
		{ID: 7, Value: Value{Kind: ValueI4, I4: -1}},
		{ID: 8, Value: Value{Kind: ValueI8, I8: 1 << 40}},
		{ID: 9, Value: Value{Kind: ValueBoolean, Boolean: true}},
	}
	lengths := map[uint16]uint64{1: 2, 2: 4, 3: 3, 4: 2, 5: 9}
	for id, want := range lengths {
		got := propertyLen(properties, id)
		if got == nil || *got != want {
			t.Fatalf("propertyLen(%d) = %v, want %d", id, got, want)
		}
	}
	if propertyLen(properties, 99) != nil {
		t.Fatal("propertyLen invented a length for an absent property")
	}
	if value := propUnsigned(properties, 6); value == nil || *value != 2 {
		t.Fatalf("propUnsigned(i2) = %v", value)
	}
	if propUnsigned(properties, 7) != nil || propUnsigned(properties, 8) != nil || propUnsigned(properties, 9) != nil {
		t.Fatal("propUnsigned accepted a negative, oversized or non-integer value")
	}
	if StorePersonal.String() != "pst" || StoreOffline.String() != "ost" {
		t.Fatal("store kind strings")
	}
}

func TestEmptyTableContext(t *testing.T) {
	fixture := newFixture(FormatUnicode512, CryptNone)
	messagePC := fixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Empty table"),
	}), true)
	table := fixture.addBlock(buildHeapBlock(tcClient, hidFor(0), [][]byte{
		tcInfoBlock([]tcColSpec{
			{tag: tag(propLTPRowID, 0x0003), offset: 0, width: 4, bit: 0},
		}, [4]uint16{4, 4, 4, 5}, 0),
	}), true)
	messageTree := fixture.addBlock(slblock(FormatUnicode512, []slEntry{
		{subnode: AttachmentTableNID, data: table.bid},
	}), true)
	fixture.nbt = []Node{{NID: 0x1004, Data: messagePC.bid, Subnode: messageTree.bid, Parent: 0x42}}
	reader := openData(t, fixture.build())

	attachments, present, err := reader.Attachments(0x1004)
	if err != nil {
		t.Fatalf("Attachments: %v", err)
	}
	if !present || len(attachments) != 0 {
		t.Fatalf("empty table present=%v rows=%d", present, len(attachments))
	}
	recipients, present, err := reader.Recipients(0x1004)
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	if present || len(recipients) != 0 {
		t.Fatalf("missing recipient table present=%v rows=%d", present, len(recipients))
	}
}

func TestBTHIndexLevel(t *testing.T) {
	layout := hidLayoutForPageBytes(512)
	header := make([]byte, 8)
	header[0] = bthType
	header[1] = bthPCKeyBytes
	header[2] = bthPCEntBytes
	header[3] = 1
	putU32(header, 4, hidFor(1))
	index := make([]byte, 6)
	putU16(index, 0, 0x3001)
	putU32(index, 2, hidFor(2))
	record := make([]byte, 8)
	putU16(record, 0, 0x3001)
	putU16(record, 2, 0x0003)
	putU32(record, 4, 42)
	heap := buildHeapBlock(pcClient, hidFor(0), [][]byte{header, index, record})
	properties, err := readPC([][]byte{heap}, layout, 100)
	if err != nil {
		t.Fatalf("readPC: %v", err)
	}
	if len(properties) != 1 || properties[0].id != 0x3001 || properties[0].kind != 0x0003 {
		t.Fatalf("BTH index properties = %+v", properties)
	}
	parsed, err := parseProperty(properties[0].id, properties[0].kind, properties[0].value.bytes, textContext{}, 100)
	if err != nil || parsed.Value.Kind != ValueI4 || parsed.Value.I4 != 42 {
		t.Fatalf("indexed property = %+v err=%v", parsed.Value, err)
	}
}

func TestArrayAttachmentData(t *testing.T) {
	fixture := newFixture(FormatUnicode512, CryptNone)
	messagePC := fixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Array attachment"),
	}), true)
	first := fixture.addBlock([]byte("he"), true)
	second := fixture.addBlock([]byte("llo"), true)
	array := fixture.addArray(1, []uint64{first.bid, second.bid}, 5)
	objectPC := fixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propAttachLongFilename, "array.bin"),
		pI4(propAttachMethod, 1),
		pI4(propAttachSize, 5),
		pSubnode(propAttachData, 0x0102, 0x03FF),
	}), true)
	objectNested := fixture.addBlock(slblock(FormatUnicode512, []slEntry{
		{subnode: 0x03FF, data: array.bid},
	}), true)
	row := make([]byte, 17)
	putU32(row, 0, 0x2001)
	putU32(row, 8, 1)
	putU32(row, 12, 5)
	row[16] = 0xF0
	table := fixture.addBlock(buildHeapBlock(tcClient, hidFor(0), [][]byte{
		tcInfoBlock([]tcColSpec{
			{tag: tag(propLTPRowID, 0x0003), offset: 0, width: 4, bit: 0},
			{tag: tag(propAttachFilename, 0x001F), offset: 4, width: 4, bit: 1},
			{tag: tag(propAttachMethod, 0x0003), offset: 8, width: 4, bit: 2},
			{tag: tag(propAttachSize, 0x0003), offset: 12, width: 4, bit: 3},
		}, [4]uint16{12, 16, 16, 17}, hidFor(1)),
		row,
	}), true)
	messageTree := fixture.addBlock(slblock(FormatUnicode512, []slEntry{
		{subnode: AttachmentTableNID, data: table.bid},
		{subnode: 0x2001, data: objectPC.bid, nested: objectNested.bid},
	}), true)
	fixture.nbt = []Node{{NID: 0x1004, Data: messagePC.bid, Subnode: messageTree.bid, Parent: 0x42}}

	reader := openData(t, fixture.build())
	attachments, present, err := reader.Attachments(0x1004)
	if err != nil || !present || len(attachments) != 1 {
		t.Fatalf("Attachments present=%v err=%v", present, err)
	}
	if attachments[0].DataBytes == nil || *attachments[0].DataBytes != 5 {
		t.Fatalf("data bytes = %v", attachments[0].DataBytes)
	}
	if attachments[0].SHA256 == nil || *attachments[0].SHA256 != expectedSHA256("hello") {
		t.Fatalf("array data sha = %v", attachments[0].SHA256)
	}
}

func TestCompressedBlockError(t *testing.T) {
	fixture := buildMainFixture(FormatUnicode4K, CryptNone, true)
	data := fixture.build()
	var target *blockRef
	for index := range fixture.blocks {
		block := &fixture.blocks[index]
		if index >= 2 && block.original > block.cb && block.bid&bitInternal == 0 {
			target = block
			break
		}
	}
	if target == nil {
		t.Skip("no compressed block in the fixture")
	}
	for offset := 0; offset < int(target.cb); offset++ {
		data[int(target.ib)+offset] = 0xFF
	}
	reader, err := Open(source.NewMemorySource(1, data), DefaultLimits())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var decodeErr error
	if _, err := reader.Messages(); err != nil {
		decodeErr = err
	} else {
		_, _, decodeErr = reader.Attachments(0x1004)
	}
	if decodeErr == nil || !errors.Is(decodeErr, source.ErrCorrupt) || !strings.Contains(decodeErr.Error(), "zlib") {
		t.Fatalf("broken zlib error = %v", decodeErr)
	}
}

func TestAnsiHeaderRefusals(t *testing.T) {
	base := buildMainFixture(FormatAnsi, CryptNone, false).build()
	cases := []struct {
		name   string
		mutate func([]byte)
		needle string
	}{
		{"sentinel", func(data []byte) { data[460] = 0 }, "sentinel"},
		{"empty-roots", func(data []byte) { putU32(data, 184, 0) }, "empty NBT"},
		{"file-eof", func(data []byte) { putU32(data, 168, uint32(len(data)+10)) }, "declares"},
		{"strong-encryption", func(data []byte) { data[461] = 3 }, "strong"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			data := append([]byte(nil), base...)
			testCase.mutate(data)
			_, err := Open(source.NewMemorySource(1, data), DefaultLimits())
			if err == nil || !strings.Contains(err.Error(), testCase.needle) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAllocationMapErrors(t *testing.T) {
	base := buildMainFixture(FormatUnicode512, CryptNone, false).build()

	badType := append([]byte(nil), base...)
	badType[0x4400+496] = 0
	reader, err := Open(source.NewMemorySource(1, badType), DefaultLimits())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := reader.AllocationMaps(); err == nil || !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "type") {
		t.Fatalf("bad map type error = %v", err)
	}

	badBID := append([]byte(nil), base...)
	putU64(badBID, 0x4400+504, 0x1234)
	reader, err = Open(source.NewMemorySource(1, badBID), DefaultLimits())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := reader.AllocationMaps(); err == nil || !strings.Contains(err.Error(), "back pointer") {
		t.Fatalf("bad map BID error = %v", err)
	}

	shortData := buildTwoLevelArrayFixture().build()[:0x4400]
	putU64(shortData, 184, uint64(len(shortData)))
	short, err := Open(source.NewMemorySource(1, shortData), DefaultLimits())
	if err != nil {
		t.Fatalf("Open short store: %v", err)
	}
	maps, err := short.AllocationMaps()
	if err != nil || len(maps) != 0 {
		t.Fatalf("maps for a short store = %d err=%v", len(maps), err)
	}
}

func TestOversizedAttachmentHash(t *testing.T) {
	data := buildMainFixture(FormatUnicode512, CryptNone, false).build()
	reader, err := Open(source.NewMemorySource(1, data), Limits{MaxAttachmentHashBytes: 2})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	attachments, present, err := reader.Attachments(0x1004)
	if err != nil || !present || len(attachments) != 1 {
		t.Fatalf("Attachments present=%v err=%v", present, err)
	}
	attachment := attachments[0]
	if attachment.DataBytes == nil || *attachment.DataBytes != 5 {
		t.Fatalf("data bytes = %v", attachment.DataBytes)
	}
	if attachment.SHA256 != nil {
		t.Fatalf("an oversized value was hashed: %v", attachment.SHA256)
	}
	if attachment.DataProblem == nil || !strings.Contains(*attachment.DataProblem, "hash limit") {
		t.Fatalf("data problem = %v", attachment.DataProblem)
	}
}

func TestHeapSpansBlocks(t *testing.T) {
	layout := hidLayoutForPageBytes(512)
	blocks := [][]byte{buildHeapBlock(tcClient, hidFor(0), [][]byte{[]byte("zero")})}
	for number := byte(1); number < 9; number++ {
		blocks = append(blocks, buildHeapPage(false, tcClient, 0, [][]byte{{number}}))
	}
	blocks = append(blocks, buildHeapPage(true, tcClient, hidFor(0), [][]byte{[]byte("nine")}))

	heap, err := parseHeap(blocks, layout)
	if err != nil {
		t.Fatalf("parseHeap: %v", err)
	}
	if heap.client != tcClient || heap.userRoot != hidFor(0) {
		t.Fatalf("heap header = %+v", heap)
	}
	first, err := heap.allocation(hidFor(0))
	if err != nil || string(first) != "zero" {
		t.Fatalf("first allocation = %q err=%v", first, err)
	}
	for number := 1; number < 9; number++ {
		value, err := heap.allocation(uint32(number)<<16 | hidFor(0))
		if err != nil || len(value) != 1 || value[0] != byte(number) {
			t.Fatalf("allocation in block %d = %v err=%v", number, value, err)
		}
	}
	last, err := heap.allocation(9<<16 | hidFor(0))
	if err != nil || string(last) != "nine" {
		t.Fatalf("bitmap-block allocation = %q err=%v", last, err)
	}
	if _, err := heap.allocation(15<<16 | hidFor(0)); err == nil {
		t.Fatal("an out-of-range heap block was accepted")
	}
}

func TestOrphanBlockRecovery(t *testing.T) {
	fixture := newFixture(FormatUnicode512, CryptNone)
	rootPC := fixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propDisplayName, "Root"),
	}), true)
	deadPC := fixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Lost"),
		pText(FormatUnicode512, propBody, "gone"),
		pBinary(propHTML, []byte("<html>gone</html>")),
		pI4(propMessageSize, 7),
	}), true)
	fixture.nbt = []Node{{NID: 0x22, Data: rootPC.bid, Parent: 0x22}}
	reader := openData(t, fixture.build())

	recovery, err := reader.RecoverDeleted()
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}
	if len(recovery.Messages) != 1 {
		t.Fatalf("recovered = %d, want 1", len(recovery.Messages))
	}
	item := recovery.Messages[0]
	if item.NID != nil {
		t.Fatalf("an orphaned block must not invent a NID: %v", item.NID)
	}
	if item.Recovery != RecoveryOrphanBlock {
		t.Fatalf("recovery kind = %v", item.Recovery)
	}
	if item.Offset == nil || *item.Offset != deadPC.ib {
		t.Fatalf("recovered offset = %v, want %d", item.Offset, deadPC.ib)
	}
	requireText(t, item.Subject, "Lost", "recovered subject")
	if !item.BodyStream || item.BodyBytes == nil || *item.BodyBytes == 0 {
		t.Fatalf("recovered body = %v / %v", item.BodyStream, item.BodyBytes)
	}
	if item.HTMLBytes == nil || *item.HTMLBytes == 0 {
		t.Fatalf("recovered html = %v", item.HTMLBytes)
	}
	if item.AttachmentCount != nil || item.RecipientCount != nil {
		t.Fatalf("a block-recovered item must not claim table counts: %v/%v", item.AttachmentCount, item.RecipientCount)
	}
	if item.Size == nil || *item.Size != 7 {
		t.Fatalf("recovered size = %v", item.Size)
	}
}

func TestPasswordEntryRefuses(t *testing.T) {
	data := buildMainFixture(FormatUnicode512, CryptNone, false).build()
	_, err := OpenWithPassword(source.NewMemorySource(1, data), DefaultLimits(), []byte("secret"))
	if !errors.Is(err, source.ErrDecrypt) {
		t.Fatalf("password error = %v", err)
	}
	if _, err := OpenWithPassword(nil, DefaultLimits(), nil); !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("nil source error = %v", err)
	}
}

func TestSubnodePageCycle(t *testing.T) {
	fixture := newFixture(FormatUnicode512, CryptNone)
	messagePC := fixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Cycle"),
	}), true)
	bid := fixture.nextExternalBID()
	index := fixture.addRawBlock(bid, slIndexBlock(FormatUnicode512, bid), true, false)
	fixture.nbt = []Node{{NID: 0x1004, Data: messagePC.bid, Subnode: index.bid, Parent: 0x42}}
	reader := openData(t, fixture.build())
	_, _, err := reader.Attachments(0x1004)
	if err == nil || !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("subnode cycle error = %v", err)
	}
}

func TestRepeatedArrayIsRefused(t *testing.T) {
	fixture := newFixture(FormatUnicode512, CryptNone)
	first := fixture.addBlock([]byte("hello "), true)
	second := fixture.addBlock([]byte("world"), true)
	total := uint64(len("hello ") + len("world"))
	xblock := fixture.addArray(1, []uint64{first.bid, second.bid}, total)
	// The XXBLOCK names the same XBLOCK twice, so expanding it would read the
	// same array repeatedly.
	xxblock := fixture.addArray(2, []uint64{xblock.bid, xblock.bid}, 2*total)
	fixture.nbt = []Node{{NID: 0x1004, Data: xxblock.bid, Parent: 0x42}}
	reader := openData(t, fixture.build())
	_, err := reader.NodeData(0x1004)
	if err == nil || !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "repeats") {
		t.Fatalf("repeated array error = %v", err)
	}
}

func TestStreamedBody(t *testing.T) {
	fixture := newFixture(FormatUnicode512, CryptNone)
	firstPart := utf16z("Streamed ")
	firstPart = firstPart[:len(firstPart)-2]
	secondPart := utf16z("body")
	firstBlock := fixture.addBlock(firstPart, true)
	secondBlock := fixture.addBlock(secondPart, true)
	total := uint64(len(firstPart) + len(secondPart))
	array := fixture.addArray(1, []uint64{firstBlock.bid, secondBlock.bid}, total)
	messagePC := fixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Streamed"),
		pSubnode(propBody, 0x001F, 0x03FF),
	}), true)
	messageTree := fixture.addBlock(slblock(FormatUnicode512, []slEntry{
		{subnode: 0x03FF, data: array.bid},
	}), true)
	fixture.nbt = []Node{{NID: 0x1004, Data: messagePC.bid, Subnode: messageTree.bid, Parent: 0x42}}
	reader := openData(t, fixture.build())
	messages, err := reader.Messages()
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("messages = %d", len(messages))
	}
	requireText(t, messages[0].Body, "Streamed body", "streamed body")
}

func TestFreeNBTAndBBTSlots(t *testing.T) {
	// A free NBT slot names an allocated block no live node references.
	nbtFixture := buildMainFixture(FormatUnicode512, CryptNone, false)
	orphanPC := nbtFixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Free slot"),
		pText(FormatUnicode512, propBody, "gone"),
	}), true)
	nbtFixture.nbtFree = []Node{
		{NID: 0x1004, Data: orphanPC.bid, Parent: 0x42}, // duplicates a live NID
		{NID: 0x1104, Data: orphanPC.bid, Parent: 0x42},
		{NID: 0x1104, Data: orphanPC.bid, Parent: 0x42}, // duplicate free slot
	}
	reader := openData(t, nbtFixture.build())
	freeNodes := reader.FreeNodes()
	if len(freeNodes) != 1 || freeNodes[0].NID != 0x1104 {
		t.Fatalf("free nodes = %+v", freeNodes)
	}
	recovery, err := reader.RecoverDeleted()
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}
	if len(recovery.Messages) != 1 || recovery.Messages[0].Recovery != RecoveryFreeNode {
		t.Fatalf("free-node recovery = %+v", recovery)
	}
	item := recovery.Messages[0]
	if item.NID == nil || *item.NID != 0x1104 {
		t.Fatalf("free-node NID = %v", item.NID)
	}
	requireText(t, item.ParentName, "Inbox", "free-node parent name")
	requireText(t, item.Subject, "Free slot", "free-node subject")

	// A free BBT slot names a block that is not in the live allocation map.
	bbtFixture := newFixture(FormatUnicode512, CryptNone)
	rootPC := bbtFixture.addBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propDisplayName, "Root"),
	}), true)
	freeBlock := bbtFixture.addOrphanBlock(pcBlock([]propSpec{
		pText(FormatUnicode512, propSubject, "Free block"),
		pText(FormatUnicode512, propBody, "gone"),
	}), true)
	bbtFixture.bbtFree = []blockRef{freeBlock, freeBlock}
	bbtFixture.nbt = []Node{{NID: 0x22, Data: rootPC.bid, Parent: 0x22}}
	reader = openData(t, bbtFixture.build())
	if reader.Stats().FreeBlockCount != 1 {
		t.Fatalf("free blocks = %d", reader.Stats().FreeBlockCount)
	}
	recovery, err = reader.RecoverDeleted()
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}
	if len(recovery.Messages) != 1 || recovery.Messages[0].Recovery != RecoveryFreeBlock {
		t.Fatalf("free-block recovery = %+v", recovery)
	}
	item = recovery.Messages[0]
	if item.NID != nil || item.Offset == nil || *item.Offset != freeBlock.ib {
		t.Fatalf("free-block item = %+v", item)
	}
	requireText(t, item.Subject, "Free block", "free-block subject")
}

func TestCorruptPageType(t *testing.T) {
	fixture := buildMainFixture(FormatUnicode512, CryptNone, false)
	data := fixture.build()
	data[fixture.nbtOffset+496] = 0x80 // NBT page claiming to be a BBT page
	_, err := Open(source.NewMemorySource(1, data), DefaultLimits())
	if err == nil || !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "type") {
		t.Fatalf("page type error = %v", err)
	}
}

func TestIncompleteReferenceWalk(t *testing.T) {
	fixture := buildMainFixture(FormatUnicode512, CryptNone, false)
	fixture.nbt[2].Subnode = 0x999999 // a BID no block B-tree entry allocates
	reader := openData(t, fixture.build())
	recovery, err := reader.RecoverDeleted()
	if err != nil {
		t.Fatalf("RecoverDeleted: %v", err)
	}
	if len(recovery.Problems) == 0 || !strings.Contains(recovery.Problems[0], "incomplete") {
		t.Fatalf("incomplete walk problems = %v", recovery.Problems)
	}
}

func TestBlockGeometryAndPageLayout(t *testing.T) {
	small := blockGeometryForFormat(FormatUnicode512)
	if alloc, err := small.allocation(0); err != nil || alloc != 64 {
		t.Fatalf("Unicode allocation(0) = %d err=%v", alloc, err)
	}
	if alloc, err := small.allocation(113); err != nil || alloc != 192 {
		t.Fatalf("Unicode allocation(113) = %d err=%v", alloc, err)
	}
	if _, err := small.allocation(8177); err == nil {
		t.Fatal("an oversized Unicode block was accepted")
	}
	ansi := blockGeometryForFormat(FormatAnsi)
	if ansi.footer != 12 || ansi.maxData() != 8180 {
		t.Fatalf("ANSI geometry = %+v", ansi)
	}
	large := blockGeometryForFormat(FormatUnicode4K)
	if alloc, err := large.allocation(172); err != nil || alloc != 512 {
		t.Fatalf("4K allocation(172) = %d err=%v", alloc, err)
	}
	if _, err := large.allocation(65_513); err == nil {
		t.Fatal("an oversized 4K block was accepted")
	}

	// The subnode layout widths and the BTPAGE footer fields.
	if subnodeLayoutForFormat(FormatAnsi).leafEntry != 12 || subnodeLayoutForFormat(FormatUnicode512).leafEntry != 24 {
		t.Fatal("subnode leaf entry sizes")
	}
	layout := pageLayoutForFormat(FormatUnicode512)
	page := make([]byte, 512)
	page[layout.count] = 3
	page[layout.maximum] = 4
	putU64(page, layout.bid, 0x1234)
	if layout.readCount(page) != 3 || layout.readMaximum(page) != 4 || layout.readBID(page) != 0x1234 {
		t.Fatal("Unicode page footer fields")
	}
	ansiLayout := pageLayoutForFormat(FormatAnsi)
	ansiPage := make([]byte, 512)
	ansiPage[ansiLayout.count] = 5
	putU32(ansiPage, ansiLayout.bid, 0x42)
	if ansiLayout.readCount(ansiPage) != 5 || ansiLayout.readBID(ansiPage) != 0x42 {
		t.Fatal("ANSI page footer fields")
	}
}
