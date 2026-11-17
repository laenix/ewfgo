// Package pst reads Microsoft Outlook folder stores: the [MS-PST] database in
// its ANSI (versions 14/15) and Unicode (versions 23 and 36) layouts.
//
// The header's content magic separates a personal folder store ("SM", ".pst")
// from an offline folder store ("SO", ".ost"); both carry the same database,
// and an OST is decoded the same way.
//
// Three layouts share the database:
//
//   - ANSI (versions 14/15): a 512-byte header, 32-bit NIDs, BIDs and file
//     offsets, 496 entry bytes per BTPAGE, 12-byte block trailers, and no
//     block compression.  The 32-bit back pointer sits before the CRC in both
//     the page footer and the block trailer; the Unicode layouts put the CRC
//     first.  PtypString8 values are the norm, so a text value is decoded with
//     the code page its property context declares, and otherwise kept
//     byte-for-byte.
//   - Unicode 512 (version 23): 564-byte header, 64-bit identifiers, 488 entry
//     bytes per BTPAGE, 16-byte block trailers.
//   - Unicode 4 KiB (version 36): 4096-byte pages, 24-byte block trailers,
//     blocks allocated in 512-byte units with an optional zlib stream.
//
// The store has four layers.  The NDB layer carries the file header, block
// allocation (the block B-tree, BBT) and the node B-tree (NBT), whose
// descriptors name a node's data BID, subnode-B-tree BID and parent NID.  The
// LTP layer is a heap-on-node (HN), a BTree-on-heap (BTH) and the property
// context (PC) or table context (TC) the BTH holds.  The MAPI layer is the
// property ids and types this package interprets.
//
// Folders are walked from the root folder NID 0x22 through NBT parent links;
// a folder no chain from the root reaches is not an allocated folder and is
// not returned.  Messages are NID type 4; associated information messages are
// type 8.  A message's attachment table is subnode 0x0671 of its own subnode
// tree and its recipient table is subnode 0x0692.  The attachment table's row
// ids name attachment objects in the message's tree; each object's property
// context, whose subnode values live in a tree of its own, supplies the names,
// times and data.  Both levels of nesting are followed.
//
// Values are only ever reported as the store records them.  An absent property
// stays nil, never zero or an empty string; a body that is not stored is
// absent.  A malformed page, a bad trailer or back pointer, a cycle, a
// malformed table or an unsupported property type is an explicit error or a
// ValueUnsupported, never a fabricated value.
//
// Encryption: NDB_CRYPT_NONE (0), NDB_CRYPT_PERMUTE (1, "compressible
// encryption") and NDB_CRYPT_CYCLIC (2) are decoded.  Any other bCryptMethod,
// including the strong-encryption values, is refused by number with
// source.ErrUnsupported.  The reference reader has no password-based
// encryption path, and neither does this one: password-protected / strongly
// encrypted stores are refused rather than guessed at.  Message bodies that
// are themselves encrypted by the sender are preserved as stored bytes and are
// not decrypted.
//
// This is a Go port of forensic-core's data/containers/pst module.  All
// offsets are validated against the source, all walks are cycle-checked and
// bounded, and no error path can panic on malformed input.
package pst

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Signature is the four-byte file signature at offset 0.
var Signature = [4]byte{'!', 'B', 'D', 'N'}

// Reader is an opened personal folder store.
type Reader struct {
	src        source.ByteSource
	header     Header
	blocks     map[uint64]blockRef
	nodes      []Node
	freeNodes  []Node
	freeBlocks []blockRef
	limits     Limits

	checksumMismatches atomic.Uint64
}

// MatchesSignature reports whether head carries the PST signature and either
// content magic.  The version is deliberately not checked: a store this
// reader refuses is still recognisably a PST, and callers should be able to
// route it here and receive a named refusal.
func MatchesSignature(head []byte) bool {
	if len(head) < 10 {
		return false
	}
	if head[0] != Signature[0] || head[1] != Signature[1] || head[2] != Signature[2] || head[3] != Signature[3] {
		return false
	}
	magic := string(head[8:10])
	return magic == MagicPST || magic == MagicOST
}

// LooksLike is an alias for MatchesSignature.
func LooksLike(head []byte) bool { return MatchesSignature(head) }

// OpenWithPassword is the explicit password entry point.  The reference
// reader implements no password-based PST/OST encryption, and neither does
// this port, so the call is refused with source.ErrDecrypt rather than
// guessing at a key or returning undecrypted bytes.  Stores using no
// encryption, compressible encryption (bCryptMethod 1) or cyclic encryption
// (2) open through [Open].
func OpenWithPassword(src source.ByteSource, limits Limits, password []byte) (*Reader, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	return nil, decryptf("password-based PST/OST encryption is not supported; no encryption, compressible (1) and cyclic (2) are the only store crypt methods decoded")
}

// Open opens a PST/OST stream and loads its node and block trees.
func Open(src source.ByteSource, limits Limits) (*Reader, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	sourceLen := src.Len()
	if sourceLen < ansiHeaderBytes {
		return nil, corruptf("a PST header is at least %d bytes, the source holds %d", ansiHeaderBytes, sourceLen)
	}
	// The version at offset 10 decides how long the header is.  Read the short
	// form first so an ANSI store is not refused for being smaller than a
	// Unicode header.
	first, err := source.ReadVecAt(src, 0, ansiHeaderBytes)
	if err != nil {
		return nil, err
	}
	version := leU16(first, 10)
	headerData := first
	if version == 23 || version == 36 {
		if sourceLen < headerBytes {
			return nil, corruptf("a Unicode PST header is %d bytes, the source holds %d", headerBytes, sourceLen)
		}
		headerData, err = source.ReadVecAt(src, 0, headerBytes)
		if err != nil {
			return nil, err
		}
	}
	header, mismatches, err := parseHeader(headerData, sourceLen)
	if err != nil {
		return nil, err
	}
	reader := &Reader{
		src:    src,
		header: header,
		blocks: make(map[uint64]blockRef),
		limits: limits.normalized(),
	}
	reader.checksumMismatches.Store(mismatches)
	blocks, freeBlocks, err := reader.walkBlocks(header.BlockRoot)
	if err != nil {
		return nil, err
	}
	reader.blocks = blocks
	nodes, freeNodes, err := reader.walkNodes(header.NodeRoot)
	if err != nil {
		return nil, err
	}
	reader.nodes = nodes

	// A slot can repeat a descriptor that the live tree also holds (a page
	// that was split and not compacted); the live copy wins.  Sort and
	// deduplicate so the recovery walk is deterministic.
	liveNIDs := make(map[uint64]struct{}, len(nodes))
	for _, node := range nodes {
		liveNIDs[node.NID] = struct{}{}
	}
	keptNodes := freeNodes[:0]
	for _, node := range freeNodes {
		if _, live := liveNIDs[node.NID]; !live {
			keptNodes = append(keptNodes, node)
		}
	}
	freeNodes = keptNodes
	sort.Slice(freeNodes, func(i, j int) bool { return freeNodes[i].NID < freeNodes[j].NID })
	freeNodes = dedupeNodes(freeNodes)

	keptBlocks := freeBlocks[:0]
	for _, block := range freeBlocks {
		if _, live := blocks[block.bid&searchMask]; !live {
			keptBlocks = append(keptBlocks, block)
		}
	}
	freeBlocks = keptBlocks
	sort.Slice(freeBlocks, func(i, j int) bool { return freeBlocks[i].bid&searchMask < freeBlocks[j].bid&searchMask })
	freeBlocks = dedupeBlocks(freeBlocks)

	reader.freeNodes = freeNodes
	reader.freeBlocks = freeBlocks
	return reader, nil
}

func dedupeNodes(nodes []Node) []Node {
	out := nodes[:0]
	for _, node := range nodes {
		if len(out) == 0 || out[len(out)-1].NID != node.NID {
			out = append(out, node)
		}
	}
	return out
}

func dedupeBlocks(blocks []blockRef) []blockRef {
	out := blocks[:0]
	for _, block := range blocks {
		if len(out) == 0 || out[len(out)-1].bid&searchMask != block.bid&searchMask {
			out = append(out, block)
		}
	}
	return out
}

// Header returns the parsed header.
func (r *Reader) Header() Header { return r.header }

// Nodes returns every NBT descriptor in NID order.
func (r *Reader) Nodes() []Node { return r.nodes }

// FreeNodes returns intact NBT descriptors found in leaf-page slots past the
// live count.
func (r *Reader) FreeNodes() []Node { return r.freeNodes }

// Node returns the descriptor for nid.
func (r *Reader) Node(nid uint64) (Node, bool) {
	index := sort.Search(len(r.nodes), func(i int) bool { return r.nodes[i].NID >= nid })
	if index < len(r.nodes) && r.nodes[index].NID == nid {
		return r.nodes[index], true
	}
	return Node{}, false
}

func (r *Reader) node(nid uint64) *Node {
	index := sort.Search(len(r.nodes), func(i int) bool { return r.nodes[i].NID >= nid })
	if index < len(r.nodes) && r.nodes[index].NID == nid {
		return &r.nodes[index]
	}
	return nil
}

// BlockCount returns the number of blocks in the BBT.
func (r *Reader) BlockCount() int { return len(r.blocks) }

// ChecksumMismatches returns block and page CRC-32 mismatches seen so far.
func (r *Reader) ChecksumMismatches() uint64 { return r.checksumMismatches.Load() }

// Stats describes the parsed store.
func (r *Reader) Stats() Stats {
	stats := Stats{
		Version:            r.header.Version,
		Format:             r.header.Format,
		ContentType:        r.header.ContentType,
		PageBytes:          r.header.PageBytes,
		CryptMethod:        r.header.CryptMethod,
		FileEOF:            r.header.FileEOF,
		NodeCount:          len(r.nodes),
		BlockCount:         len(r.blocks),
		FreeNodeCount:      len(r.freeNodes),
		FreeBlockCount:     len(r.freeBlocks),
		ChecksumMismatches: r.checksumMismatches.Load(),
	}
	for _, node := range r.nodes {
		switch {
		case node.IsFolder():
			stats.FolderNodes++
		case node.IsMessage():
			stats.MessageNodes++
		case node.IsAssociatedMessage():
			stats.AssociatedMessageNodes++
		}
	}
	return stats
}

// RootFolder returns the NID of the root folder (0x22) when the store has one.
func (r *Reader) RootFolder() (uint64, bool) {
	node := r.node(rootFolderNID)
	if node == nil || !node.IsFolder() {
		return 0, false
	}
	return node.NID, true
}

// reachableNIDs returns the NIDs a folder chain from the root reaches, or nil
// when the store has no root folder (so reachability cannot be established).
func (r *Reader) reachableNIDs() map[uint64]struct{} {
	root, ok := r.RootFolder()
	if !ok {
		return nil
	}
	children := make(map[uint64][]uint64)
	for _, node := range r.nodes {
		if node.IsFolder() {
			children[uint64(node.Parent)] = append(children[uint64(node.Parent)], node.NID)
		}
	}
	reachable := make(map[uint64]struct{})
	stack := []uint64{root}
	for len(stack) > 0 {
		nid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, seen := reachable[nid]; seen {
			continue
		}
		reachable[nid] = struct{}{}
		stack = append(stack, children[nid]...)
	}
	for _, node := range r.nodes {
		if node.IsMessage() || node.IsAssociatedMessage() {
			if _, parentReachable := reachable[uint64(node.Parent)]; parentReachable {
				reachable[node.NID] = struct{}{}
			}
		}
	}
	return reachable
}

func isReachable(reachable map[uint64]struct{}, nid uint64) bool {
	if reachable == nil {
		return true
	}
	_, ok := reachable[nid]
	return ok
}

// Folders returns every reachable folder node, with its properties and the
// parent/child links the NBT records.
func (r *Reader) Folders() ([]Folder, error) {
	reachable := r.reachableNIDs()
	folders := make([]Folder, 0)
	index := make(map[uint64]int)
	for _, node := range r.nodes {
		if !node.IsFolder() || !isReachable(reachable, node.NID) {
			continue
		}
		properties, err := r.propertiesOf(&node)
		if err != nil {
			return nil, err
		}
		folder := Folder{
			NID:        node.NID,
			Parent:     uint64(node.Parent),
			Name:       propText(properties, propDisplayName),
			DataBID:    node.Data,
			SubnodeBID: node.Subnode,
			PageOffset: node.PageOffset,
		}
		if content := propI4(properties, propContentCount); content != nil && *content >= 0 {
			value := uint32(*content)
			folder.ContentCount = &value
		}
		folder.DataOffset, _ = r.dataOffset(node.Data, 0)
		index[node.NID] = len(folders)
		folders = append(folders, folder)
		if len(folders) > r.limits.MaxItems {
			return nil, limitf("the store holds more than %d reachable folders", r.limits.MaxItems)
		}
	}
	for _, node := range r.nodes {
		parent := uint64(node.Parent)
		slot, ok := index[parent]
		if !ok || !isReachable(reachable, node.NID) {
			continue
		}
		if node.IsFolder() {
			if node.NID != parent {
				folders[slot].ChildFolders = append(folders[slot].ChildFolders, node.NID)
			}
		} else if node.IsMessage() {
			folders[slot].MessageCount++
		}
	}
	return folders, nil
}

// Messages returns every message the store records, in NID order: ordinary
// messages (NID type 4) and associated information messages (type 8).
func (r *Reader) Messages() ([]Message, error) {
	reachable := r.reachableNIDs()
	messages := make([]Message, 0)
	for index := range r.nodes {
		node := &r.nodes[index]
		if !(node.IsMessage() || node.IsAssociatedMessage()) || !isReachable(reachable, node.NID) {
			continue
		}
		message, err := r.messageOf(node)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
		if len(messages) > r.limits.MaxItems {
			return nil, limitf("the store holds more than %d reachable messages", r.limits.MaxItems)
		}
	}
	return messages, nil
}

// Message returns one message from a node discovered through Nodes.
func (r *Reader) Message(nid uint64) (Message, error) {
	node := r.node(nid)
	if node == nil {
		return Message{}, corruptf("no node 0x%X in the NBT", nid)
	}
	return r.messageOf(node)
}

func (r *Reader) messageOf(node *Node) (Message, error) {
	if !node.IsMessage() && !node.IsAssociatedMessage() {
		return Message{}, corruptf("node 0x%X is not a message (NID type %d)", node.NID, node.Kind())
	}
	properties, err := r.propertiesOf(node)
	if err != nil {
		return Message{}, err
	}
	senderEmail, senderSource := senderOf(properties)
	message := Message{
		NID:               node.NID,
		Folder:            uint64(node.Parent),
		Associated:        node.IsAssociatedMessage(),
		Subject:           propText(properties, propSubject),
		SenderName:        propText(properties, propSenderName),
		SenderEmail:       senderEmail,
		SenderEmailSource: senderSource,
		MessageClass:      propText(properties, propMessageClass),
		SubmitTime:        propTime(properties, propClientSubmitTime),
		DeliveryTime:      propTime(properties, propDeliveryTime),
		Body:              propText(properties, propBody),
		HTML:              propBinary(properties, propHTML),
		RTF:               propBinary(properties, propRTFCompressed),
		TransportHeaders:  propText(properties, propTransportHeaders),
		MessageID:         propText(properties, propInternetMessageID),
		DisplayTo:         displayList(properties, propDisplayTo),
		DisplayCc:         displayList(properties, propDisplayCc),
		DisplayBcc:        displayList(properties, propDisplayBcc),
		HasAttachments:    propBool(properties, propHasAttachments),
		DataBID:           node.Data,
		SubnodeBID:        node.Subnode,
		PageOffset:        node.PageOffset,
	}
	if size := propI4(properties, propMessageSize); size != nil && *size >= 0 {
		value := uint32(*size)
		message.Size = &value
	}
	if flags := propI4(properties, propMessageFlags); flags != nil && *flags >= 0 {
		value := uint32(*flags)
		message.Flags = &value
	}
	message.DataOffset, _ = r.dataOffset(node.Data, 0)
	return message, nil
}

// NodeData returns the node's data (the LTP heap), following XBLOCK/XXBLOCK
// arrays and decoding the NDB encryption.
func (r *Reader) NodeData(nid uint64) ([]byte, error) {
	blocks, err := r.NodeBlocks(nid)
	if err != nil {
		return nil, err
	}
	total := 0
	for _, block := range blocks {
		total += len(block)
	}
	data := make([]byte, 0, total)
	for _, block := range blocks {
		data = append(data, block...)
	}
	return data, nil
}

// NodeBlocks returns the node's data as separate blocks.  A heap spans them,
// and a HID's high word selects which one holds a value.
func (r *Reader) NodeBlocks(nid uint64) ([][]byte, error) {
	node := r.node(nid)
	if node == nil {
		return nil, corruptf("no node 0x%X in the NBT", nid)
	}
	return r.nodeBlocksOf(node)
}

func (r *Reader) nodeBlocksOf(node *Node) ([][]byte, error) {
	if node.Data == 0 {
		return nil, nil
	}
	var blocks [][]byte
	if _, err := r.expandData(node.Data, 0, &blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}

// Properties returns the node's property context, typed by MAPI property
// type.
func (r *Reader) Properties(nid uint64) ([]Property, error) {
	node := r.node(nid)
	if node == nil {
		return nil, corruptf("no node 0x%X in the NBT", nid)
	}
	return r.propertiesOf(node)
}

func (r *Reader) propertiesOf(node *Node) ([]Property, error) {
	blocks, err := r.nodeBlocksOf(node)
	if err != nil {
		return nil, err
	}
	if len(blocks) == 0 {
		return nil, nil
	}
	label := fmt.Sprintf("node 0x%X", node.NID)
	raw, err := r.readPCRaw(label, blocks)
	if err != nil {
		return nil, err
	}
	needsSubnodes := false
	for _, property := range raw {
		if property.value.kind == rawSubnode {
			needsSubnodes = true
			break
		}
	}
	subnodes := map[uint32]subnodeEntry{}
	if needsSubnodes {
		subnodes, err = r.subnodeEntriesOf(node)
		if err != nil {
			return nil, err
		}
	}
	return r.resolveProperties(label, raw, subnodes)
}

// propertiesFromBlock reads a property context held in one block with no
// subnode tree to resolve.  A value stored in a subnode is skipped: without
// the tree its bytes are not available, and inventing them is worse than
// leaving the field absent.
func (r *Reader) propertiesFromBlock(label string, block []byte) ([]Property, error) {
	layout := hidLayoutForPageBytes(r.header.PageBytes)
	raw, err := readPC([][]byte{block}, layout, r.limits.MaxProperties)
	if err != nil {
		return nil, corruptf("the property context of %s: %v", label, err)
	}
	text := r.textContext(raw)
	properties := make([]Property, 0, len(raw))
	for _, property := range raw {
		if property.value.kind != rawHeap {
			continue
		}
		parsed, err := parseProperty(property.id, property.kind, property.value.bytes, text, r.limits.MaxMultiValues)
		if err != nil {
			return nil, err
		}
		properties = append(properties, parsed)
	}
	return properties, nil
}

func (r *Reader) readPCRaw(label string, blocks [][]byte) ([]rawProperty, error) {
	layout := hidLayoutForPageBytes(r.header.PageBytes)
	raw, err := readPC(blocks, layout, r.limits.MaxProperties)
	if err != nil {
		return nil, corruptf("the property context of %s (%d block(s)): %v", label, len(blocks), err)
	}
	return raw, nil
}

func (r *Reader) resolveProperties(label string, raw []rawProperty, tree map[uint32]subnodeEntry) ([]Property, error) {
	text := r.textContext(raw)
	properties := make([]Property, 0, len(raw))
	for _, property := range raw {
		var value []byte
		switch property.value.kind {
		case rawHeap:
			value = property.value.bytes
		case rawSubnode:
			resolved, err := r.subnodeData(label, tree, property.value.subnode)
			if err != nil {
				return nil, err
			}
			value = resolved
		default:
			return nil, corruptf("property 0x%04X has an unknown storage kind", property.id)
		}
		parsed, err := parseProperty(property.id, property.kind, value, text, r.limits.MaxMultiValues)
		if err != nil {
			return nil, err
		}
		properties = append(properties, parsed)
	}
	return properties, nil
}

func (r *Reader) textContext(raw []rawProperty) textContext {
	codepage, ok := declaredCodepage(raw)
	return textContext{ansi: r.header.Format.IsAnsi(), codepage: codepage, hasCodepage: ok}
}

func (r *Reader) subnodeEntries(nid uint64) (map[uint32]subnodeEntry, error) {
	node := r.node(nid)
	if node == nil {
		return nil, corruptf("no node 0x%X in the NBT", nid)
	}
	return r.subnodeEntriesOf(node)
}

func (r *Reader) subnodeEntriesOf(node *Node) (map[uint32]subnodeEntry, error) {
	if node.Subnode == 0 {
		return map[uint32]subnodeEntry{}, nil
	}
	return r.subnodeTree(node.Subnode)
}

func (r *Reader) subnodeTree(bid uint64) (map[uint32]subnodeEntry, error) {
	entries := make(map[uint32]subnodeEntry)
	visited := make(map[uint64]struct{})
	pages := 0
	if err := r.collectSubnodePage(bid, 0, entries, visited, &pages); err != nil {
		return nil, err
	}
	return entries, nil
}

func (r *Reader) collectSubnodePage(bid uint64, depth uint8, out map[uint32]subnodeEntry, visited map[uint64]struct{}, pages *int) error {
	if depth > maxSubnodeLevels {
		return corruptf("the subnode tree nests more than %d levels", maxSubnodeLevels)
	}
	key := bid & searchMask
	if _, seen := visited[key]; seen {
		return corruptf("subnode page cycle at BID 0x%X", bid)
	}
	visited[key] = struct{}{}
	*pages++
	if *pages > r.limits.MaxPages {
		return limitf("the subnode tree has more than %d pages", r.limits.MaxPages)
	}
	layout := subnodeLayoutForFormat(r.header.Format)
	raw, err := r.readBlock(bid, true)
	if err != nil {
		return err
	}
	if len(raw) < layout.header {
		return corruptf("subnode page BID 0x%X is %d bytes, shorter than its header", bid, len(raw))
	}
	if raw[0] != subtreePageType {
		return corruptf("subnode page BID 0x%X has type 0x%02X, not 0x%02X", bid, raw[0], subtreePageType)
	}
	level := raw[1]
	count := int(leU16(raw, 2))
	entry := layout.leafEntry
	if level != 0 {
		entry = layout.indexEntry
	}
	if entry <= 0 || count > (len(raw)-layout.header)/entry {
		return corruptf("subnode page BID 0x%X declares %d entries, past its %d bytes", bid, count, len(raw))
	}
	for index := 0; index < count; index++ {
		at := layout.header + index*entry
		if level == 0 {
			subnode, data, nested := layout.leaf(raw, at)
			if data == 0 {
				return corruptf("subnode 0x%X names no data block", subnode)
			}
			out[uint32(subnode)] = subnodeEntry{data: data, nested: nested}
		} else {
			child := layout.index(raw, at)
			if child == 0 {
				return corruptf("subnode index page BID 0x%X names no child at entry %d", bid, index)
			}
			if err := r.collectSubnodePage(child, depth+1, out, visited, pages); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Reader) subnodeData(label string, entries map[uint32]subnodeEntry, subnode uint32) ([]byte, error) {
	blocks, err := r.subnodeBlocks(label, entries, subnode)
	if err != nil {
		return nil, err
	}
	total := 0
	for _, block := range blocks {
		total += len(block)
	}
	data := make([]byte, 0, total)
	for _, block := range blocks {
		data = append(data, block...)
	}
	return data, nil
}

func (r *Reader) subnodeBlocks(label string, entries map[uint32]subnodeEntry, subnode uint32) ([][]byte, error) {
	bid, err := r.subnodeBID(label, entries, subnode)
	if err != nil {
		return nil, err
	}
	var blocks [][]byte
	if _, err := r.expandData(bid, 0, &blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}

func (r *Reader) subnodeBID(label string, entries map[uint32]subnodeEntry, subnode uint32) (uint64, error) {
	entry, ok := entries[subnode]
	if !ok {
		return 0, corruptf("%s names subnode 0x%08X, which its subnode tree does not hold (%d entries)", label, subnode, len(entries))
	}
	return entry.data, nil
}

func (r *Reader) nestedTree(label string, entry subnodeEntry) (map[uint32]subnodeEntry, error) {
	if entry.nested == 0 {
		return map[uint32]subnodeEntry{}, nil
	}
	tree, err := r.subnodeTree(entry.nested)
	if err != nil {
		return nil, corruptf("the nested subnode tree of %s: %v", label, err)
	}
	return tree, nil
}

// dataLength returns the number of data bytes a BID contributes, from the
// block B-tree and any array headers alone.
func (r *Reader) dataLength(bid uint64, depth uint8) (uint64, error) {
	return r.dataLengthSeen(bid, depth, make(map[uint64]struct{}))
}

func (r *Reader) dataLengthSeen(bid uint64, depth uint8, seen map[uint64]struct{}) (uint64, error) {
	if bid&bitInternal == 0 {
		reference, err := r.blockRef(bid)
		if err != nil {
			return 0, err
		}
		stored := uint64(reference.cb)
		original := uint64(reference.original)
		if original > stored {
			return original, nil
		}
		return stored, nil
	}
	key := bid & searchMask
	if _, repeated := seen[key]; repeated {
		return 0, corruptf("the data tree at BID 0x%X repeats an array", bid)
	}
	seen[key] = struct{}{}
	if depth >= 2 {
		return 0, corruptf("the data tree nests more than two array levels")
	}
	raw, err := r.readBlock(bid, false)
	if err != nil {
		return 0, err
	}
	array, err := parseArray(raw, bid, r.header.Format)
	if err != nil {
		return 0, err
	}
	total := uint64(0)
	for _, child := range array.bids {
		childLength, err := r.dataLengthSeen(child, depth+1, seen)
		if err != nil {
			return 0, err
		}
		total += childLength
	}
	if total != array.total {
		return 0, corruptf("the array at BID 0x%X declares %d bytes but its entries hold %d", bid, array.total, total)
	}
	return total, nil
}

// expandData expands one data BID into out, returning the number of bytes it
// contributes.
func (r *Reader) expandData(bid uint64, depth uint8, out *[][]byte) (uint64, error) {
	return r.expandDataSeen(bid, depth, out, make(map[uint64]struct{}))
}

func (r *Reader) expandDataSeen(bid uint64, depth uint8, out *[][]byte, seen map[uint64]struct{}) (uint64, error) {
	if bid&bitInternal == 0 {
		data, err := r.readBlock(bid, true)
		if err != nil {
			return 0, err
		}
		total := uint64(len(data))
		for _, block := range *out {
			total += uint64(len(block))
		}
		if total > r.limits.MaxNodeData {
			return 0, limitf("node data exceeds %d bytes", r.limits.MaxNodeData)
		}
		*out = append(*out, data)
		return uint64(len(data)), nil
	}
	key := bid & searchMask
	if _, repeated := seen[key]; repeated {
		return 0, corruptf("the data tree at BID 0x%X repeats an array", bid)
	}
	seen[key] = struct{}{}
	if depth >= 2 {
		return 0, corruptf("the data tree nests more than two array levels")
	}
	raw, err := r.readBlock(bid, false)
	if err != nil {
		return 0, err
	}
	array, err := parseArray(raw, bid, r.header.Format)
	if err != nil {
		return 0, err
	}
	if array.total > r.limits.MaxNodeData {
		return 0, limitf("an array at BID 0x%X declares %d bytes of node data", bid, array.total)
	}
	written := uint64(0)
	for _, child := range array.bids {
		childInternal := child&bitInternal != 0
		if array.level == 1 && childInternal {
			return 0, corruptf("XBLOCK 0x%X lists internal block 0x%X as data", bid, child)
		}
		if array.level == 2 && !childInternal {
			return 0, corruptf("XXBLOCK 0x%X lists external block 0x%X as an XBLOCK", bid, child)
		}
		contributed, err := r.expandDataSeen(child, depth+1, out, seen)
		if err != nil {
			return 0, err
		}
		written += contributed
	}
	if written != array.total {
		return 0, corruptf("the array at BID 0x%X declares %d bytes but its entries hold %d", bid, array.total, written)
	}
	return written, nil
}

func (r *Reader) blockRef(bid uint64) (blockRef, error) {
	reference, ok := r.blocks[bid&searchMask]
	if !ok {
		return blockRef{}, corruptf("BID 0x%X is not in the block B-tree (%d blocks)", bid, len(r.blocks))
	}
	return reference, nil
}

func (r *Reader) readBlock(bid uint64, encoded bool) ([]byte, error) {
	reference, err := r.blockRef(bid)
	if err != nil {
		return nil, err
	}
	return r.decodeBlock(reference, encoded)
}

func (r *Reader) decodeBlock(reference blockRef, encoded bool) ([]byte, error) {
	geometry := blockGeometryForFormat(r.header.Format)
	cb := int(reference.cb)
	if cb > geometry.maxData() {
		return nil, corruptf("BID 0x%X declares %d data bytes; a block holds at most %d", reference.bid, cb, geometry.maxData())
	}
	alloc, err := geometry.allocation(cb)
	if err != nil {
		return nil, err
	}
	end := reference.ib + uint64(alloc)
	if end < reference.ib {
		return nil, corruptf("the block offset overflows")
	}
	if end > r.src.Len() {
		return nil, corruptf("BID 0x%X runs to offset %d, past the %d-byte source", reference.bid, end, r.src.Len())
	}
	raw, err := source.ReadVecAt(r.src, reference.ib, uint64(alloc))
	if err != nil {
		return nil, err
	}
	if len(raw) < geometry.footer {
		return nil, corruptf("BID 0x%X allocation is shorter than its %d-byte trailer", reference.bid, geometry.footer)
	}
	trailer := raw[alloc-geometry.footer:]
	storedCb := int(leU16(trailer, 0))
	storedSignature := leU16(trailer, 2)
	var storedBID uint64
	var storedCRC uint32
	if r.header.Format.IsAnsi() {
		storedBID = uint64(leU32(trailer, 4))
		storedCRC = leU32(trailer, 8)
	} else {
		storedCRC = leU32(trailer, 4)
		storedBID = leU64(trailer, 8)
	}
	if storedCb != cb {
		return nil, corruptf("BID 0x%X is %d bytes in the BBT but %d in its trailer", reference.bid, cb, storedCb)
	}
	if storedBID != reference.bid {
		return nil, corruptf("BID 0x%X carries back pointer 0x%X", reference.bid, storedBID)
	}
	expected := blockSignature(reference.ib, storedBID)
	if storedSignature != expected {
		return nil, corruptf("BID 0x%X has signature 0x%04X, not 0x%04X", reference.bid, storedSignature, expected)
	}
	if crc32PST(raw[:cb]) != storedCRC {
		r.checksumMismatches.Add(1)
	}
	data := append([]byte(nil), raw[:cb]...)
	if encoded {
		switch r.header.CryptMethod {
		case CryptNone:
		case CryptPermute:
			permute(data, false)
		case CryptCyclic:
			cyclic(data, storedBID)
		default:
			return nil, unsupportedf("NDB crypt method 0x%02X", r.header.CryptMethod)
		}
	}
	if int(reference.original) > cb {
		data, err = inflateBlock(data, int(reference.original), reference.bid&searchMask)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

func inflateBlock(stored []byte, original int, bid uint64) ([]byte, error) {
	decoder, err := zlib.NewReader(bytes.NewReader(stored))
	if err != nil {
		return nil, corruptf("BID 0x%X holds a broken zlib stream: %v", bid, err)
	}
	defer decoder.Close()
	out, err := io.ReadAll(io.LimitReader(decoder, int64(original)+1))
	if err != nil {
		return nil, corruptf("BID 0x%X holds a broken zlib stream: %v", bid, err)
	}
	if len(out) != original {
		return nil, corruptf("BID 0x%X decompresses to %d bytes, not the %d its BBT entry declares", bid, len(out), original)
	}
	return out, nil
}

// pageKind is which B-tree a BTPAGE belongs to.
type pageKind uint8

const (
	pageKindNode pageKind = iota
	pageKindBlock
)

func (k pageKind) ptype() byte {
	if k == pageKindNode {
		return nbtPageType
	}
	return bbtPageType
}

func (k pageKind) leafEntry(format StoreFormat) int {
	if k == pageKindNode {
		if format.IsAnsi() {
			return 16
		}
		return 32
	}
	if format.IsAnsi() {
		return 12
	}
	return 24
}

func branchEntryBytes(format StoreFormat) int {
	if format.IsAnsi() {
		return 12
	}
	return 24
}

// pageLayout is where a BTPAGE keeps its footer.
type pageLayout struct {
	pageBytes int
	entries   int
	count     int
	countSize int
	maximum   int
	entrySize int
	level     int
	ptype     int
	crc       int
	crcCover  int
	bid       int
	bidBytes  int
}

func pageLayoutForFormat(format StoreFormat) pageLayout {
	switch format {
	case FormatAnsi:
		return pageLayout{pageBytes: 512, entries: 496, count: 496, countSize: 1, maximum: 497, entrySize: 498, level: 499, ptype: 500, crc: 508, crcCover: 500, bid: 504, bidBytes: 4}
	case FormatUnicode512:
		return pageLayout{pageBytes: 512, entries: 488, count: 488, countSize: 1, maximum: 489, entrySize: 490, level: 491, ptype: 496, crc: 500, crcCover: 496, bid: 504, bidBytes: 8}
	default:
		return pageLayout{pageBytes: 4096, entries: 4056, count: 4056, countSize: 2, maximum: 4058, entrySize: 4060, level: 4061, ptype: 4072, crc: 4076, crcCover: 4072, bid: 4080, bidBytes: 8}
	}
}

func (l pageLayout) readBID(buf []byte) uint64 {
	if l.bidBytes == 4 {
		return uint64(leU32(buf, l.bid))
	}
	return leU64(buf, l.bid)
}

func (l pageLayout) readCount(buf []byte) int {
	if l.countSize == 2 {
		return int(leU16(buf, l.count))
	}
	return int(buf[l.count])
}

func (l pageLayout) readMaximum(buf []byte) int {
	if l.countSize == 2 {
		return int(leU16(buf, l.maximum))
	}
	return int(buf[l.maximum])
}

func (r *Reader) readBTPage(bid *uint64, ib uint64, kind pageKind) (*btPage, error) {
	format := r.header.Format
	layout := pageLayoutForFormat(format)
	end := ib + uint64(layout.pageBytes)
	if end < ib {
		return nil, corruptf("the page offset overflows")
	}
	if end > r.src.Len() {
		return nil, corruptf("a page at offset %d runs past the %d-byte source", ib, r.src.Len())
	}
	buf, err := source.ReadVecAt(r.src, ib, uint64(layout.pageBytes))
	if err != nil {
		return nil, err
	}
	if buf[layout.ptype] != kind.ptype() || buf[layout.ptype+1] != buf[layout.ptype] {
		return nil, corruptf("page at offset %d has type 0x%02X/0x%02X, expected 0x%02X", ib, buf[layout.ptype], buf[layout.ptype+1], kind.ptype())
	}
	pageBID := layout.readBID(buf)
	if bid != nil && pageBID != *bid {
		return nil, corruptf("page at offset %d carries back pointer 0x%X, not 0x%X", ib, pageBID, *bid)
	}
	if pageBID == 0 {
		return nil, corruptf("page at offset %d has no back pointer", ib)
	}
	if format.IsAnsi() {
		stored := leU16(buf, layout.ptype+2)
		expected := blockSignature(ib, pageBID)
		if stored != expected {
			return nil, corruptf("page at offset %d has signature 0x%04X, not 0x%04X", ib, stored, expected)
		}
	}
	if crc32PST(buf[:layout.crcCover]) != leU32(buf, layout.crc) {
		r.checksumMismatches.Add(1)
	}
	count := layout.readCount(buf)
	maximum := layout.readMaximum(buf)
	entrySize := int(buf[layout.entrySize])
	level := buf[layout.level]
	if entrySize == 0 || count > maximum || count*entrySize > layout.entries || maximum*entrySize > layout.entries {
		return nil, corruptf("page at offset %d declares %d of %d entries of %d bytes", ib, count, maximum, entrySize)
	}
	expectedEntry := branchEntryBytes(format)
	if level == 0 {
		expectedEntry = kind.leafEntry(format)
	}
	if entrySize != expectedEntry {
		return nil, corruptf("page at offset %d at level %d uses %d-byte entries, not %d", ib, level, entrySize, expectedEntry)
	}
	return &btPage{buf: buf, count: count, maximum: maximum, entrySize: entrySize, level: level}, nil
}

func (p *btPage) entry(index int) []byte {
	at := index * p.entrySize
	return p.buf[at : at+p.entrySize]
}

func (r *Reader) walkNodes(root Bref) ([]Node, []Node, error) {
	nodes := make([]Node, 0)
	free := make([]Node, 0)
	visited := make(map[uint64]struct{})
	pages := 0
	var previous *uint64
	rootBID := root.BID
	if err := r.collectNodes(&rootBID, root.IB, &nodes, &free, &previous, visited, &pages); err != nil {
		return nil, nil, err
	}
	return nodes, free, nil
}

func (r *Reader) collectNodes(bid *uint64, ib uint64, out, free *[]Node, previous **uint64, visited map[uint64]struct{}, pages *int) error {
	if _, seen := visited[ib]; seen {
		return corruptf("NBT page cycle at offset %d", ib)
	}
	visited[ib] = struct{}{}
	*pages++
	if *pages > r.limits.MaxPages {
		return limitf("the NBT has more than %d pages", r.limits.MaxPages)
	}
	page, err := r.readBTPage(bid, ib, pageKindNode)
	if err != nil {
		return err
	}
	if page.level > maxBTLevels {
		return corruptf("the NBT declares %d index levels", page.level)
	}
	ansi := r.header.Format.IsAnsi()
	if page.level == 0 {
		for index := 0; index < page.count; index++ {
			node := nbtLeafEntry(page.entry(index), ansi)
			node.PageOffset = ib
			if *previous != nil && node.NID <= **previous {
				return corruptf("NBT node 0x%X follows 0x%X; the NBT is not ordered", node.NID, **previous)
			}
			value := node.NID
			*previous = &value
			*out = append(*out, node)
			if len(*out) > r.limits.MaxNodes {
				return limitf("the NBT holds more than %d nodes", r.limits.MaxNodes)
			}
		}
		for index := page.count; index < page.maximum; index++ {
			node := nbtLeafEntry(page.entry(index), ansi)
			if node.NID == 0 || node.Data == 0 {
				continue
			}
			switch node.Kind() {
			case nidTypeFolder, nidTypeSearchFolder, nidTypeMessage, nidTypeAssociatedMsg:
				node.PageOffset = ib
				*free = append(*free, node)
			}
		}
		return nil
	}
	for index := 0; index < page.count; index++ {
		childBID, childIB := nbtBranchEntry(page.entry(index), ansi)
		if err := r.collectNodes(&childBID, childIB, out, free, previous, visited, pages); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reader) walkBlocks(root Bref) (map[uint64]blockRef, []blockRef, error) {
	blocks := make(map[uint64]blockRef)
	free := make([]blockRef, 0)
	visited := make(map[uint64]struct{})
	pages := 0
	rootBID := root.BID
	if err := r.collectBlocks(&rootBID, root.IB, blocks, &free, visited, &pages); err != nil {
		return nil, nil, err
	}
	return blocks, free, nil
}

func (r *Reader) collectBlocks(bid *uint64, ib uint64, out map[uint64]blockRef, free *[]blockRef, visited map[uint64]struct{}, pages *int) error {
	if _, seen := visited[ib]; seen {
		return corruptf("BBT page cycle at offset %d", ib)
	}
	visited[ib] = struct{}{}
	*pages++
	if *pages > r.limits.MaxPages {
		return limitf("the BBT has more than %d pages", r.limits.MaxPages)
	}
	page, err := r.readBTPage(bid, ib, pageKindBlock)
	if err != nil {
		return err
	}
	ansi := r.header.Format.IsAnsi()
	if page.level == 0 {
		for index := 0; index < page.count; index++ {
			reference := bbtLeafEntry(page.entry(index), ansi)
			key := reference.bid & searchMask
			if _, exists := out[key]; exists {
				return corruptf("BBT lists BID 0x%X twice", reference.bid)
			}
			out[key] = reference
			if len(out) > r.limits.MaxBlocks {
				return limitf("the BBT holds more than %d blocks", r.limits.MaxBlocks)
			}
		}
		for index := page.count; index < page.maximum; index++ {
			reference := bbtLeafEntry(page.entry(index), ansi)
			if reference.bid == 0 || reference.ib == 0 || reference.cb == 0 {
				continue
			}
			*free = append(*free, reference)
		}
		return nil
	}
	if page.level > maxBTLevels {
		return corruptf("the BBT declares %d index levels", page.level)
	}
	for index := 0; index < page.count; index++ {
		childBID, childIB := bbtBranchEntry(page.entry(index), ansi)
		if err := r.collectBlocks(&childBID, childIB, out, free, visited, pages); err != nil {
			return err
		}
	}
	return nil
}

// nbtLeafEntry parses one NBT leaf descriptor.
func nbtLeafEntry(entry []byte, ansi bool) Node {
	if ansi {
		return Node{
			NID:     uint64(leU32(entry, 0)),
			Data:    uint64(leU32(entry, 4)),
			Subnode: uint64(leU32(entry, 8)),
			Parent:  leU32(entry, 12),
		}
	}
	return Node{
		NID:     leU64(entry, 0),
		Data:    leU64(entry, 8),
		Subnode: leU64(entry, 16),
		Parent:  leU32(entry, 24),
	}
}

func nbtBranchEntry(entry []byte, ansi bool) (uint64, uint64) {
	if ansi {
		return uint64(leU32(entry, 4)), uint64(leU32(entry, 8))
	}
	return leU64(entry, 8), leU64(entry, 16)
}

func bbtLeafEntry(entry []byte, ansi bool) blockRef {
	if ansi {
		return blockRef{bid: uint64(leU32(entry, 0)), ib: uint64(leU32(entry, 4)), cb: leU16(entry, 8)}
	}
	return blockRef{bid: leU64(entry, 0), ib: leU64(entry, 8), cb: leU16(entry, 16), original: leU16(entry, 18)}
}

func bbtBranchEntry(entry []byte, ansi bool) (uint64, uint64) {
	if ansi {
		return uint64(leU32(entry, 4)), uint64(leU32(entry, 8))
	}
	return leU64(entry, 8), leU64(entry, 16)
}

// blockGeometry is how one store layout lays out NDB blocks.
type blockGeometry struct {
	increment int
	footer    int
	maxAlloc  int
}

func blockGeometryForFormat(format StoreFormat) blockGeometry {
	switch format {
	case FormatAnsi:
		return blockGeometry{increment: blockIncrement512, footer: blockFooterBytesANSI, maxAlloc: maxBlockAlloc512}
	case FormatUnicode512:
		return blockGeometry{increment: blockIncrement512, footer: blockFooterBytes512, maxAlloc: maxBlockAlloc512}
	default:
		return blockGeometry{increment: blockIncrement4K, footer: blockFooterBytes4K, maxAlloc: maxBlockAlloc4K}
	}
}

func (g blockGeometry) maxData() int { return g.maxAlloc - g.footer }

func (g blockGeometry) allocation(dataSize int) (int, error) {
	alloc := ((dataSize + g.footer + g.increment - 1) / g.increment) * g.increment
	if alloc == 0 || alloc > g.maxAlloc {
		return 0, corruptf("a %d-byte block needs %d bytes, the maximum is %d", dataSize, alloc, g.maxAlloc)
	}
	return alloc, nil
}

// array is an XBLOCK (level 1) or XXBLOCK (level 2) header and BID array.
type array struct {
	level uint8
	total uint64
	bids  []uint64
}

func parseArray(data []byte, bid uint64, format StoreFormat) (array, error) {
	if len(data) < 8 {
		return array{}, corruptf("array block 0x%X holds only %d bytes", bid, len(data))
	}
	if data[0] != arrayType {
		return array{}, corruptf("internal block 0x%X has type 0x%02X, not 0x%02X", bid, data[0], arrayType)
	}
	level := data[1]
	if level != 1 && level != 2 {
		return array{}, corruptf("array block 0x%X has indirection level %d, not 1 or 2", bid, level)
	}
	count := int(leU16(data, 2))
	total := uint64(leU32(data, 4))
	bidBytes := 8
	if format.IsAnsi() {
		bidBytes = 4
	}
	if count > (len(data)-8)/bidBytes {
		return array{}, corruptf("array block 0x%X declares %d BIDs in %d bytes", bid, count, len(data))
	}
	bids := make([]uint64, 0, count)
	for index := 0; index < count; index++ {
		at := 8 + index*bidBytes
		if bidBytes == 4 {
			bids = append(bids, uint64(leU32(data, at)))
		} else {
			bids = append(bids, leU64(data, at))
		}
	}
	return array{level: level, total: total, bids: bids}, nil
}

// subnodeLayout is where a subnode BTree page keeps its header and entries.
type subnodeLayout struct {
	header     int
	leafEntry  int
	indexEntry int
	ansi       bool
}

func subnodeLayoutForFormat(format StoreFormat) subnodeLayout {
	if format.IsAnsi() {
		return subnodeLayout{header: subtreeHeaderANSI, leafEntry: subtreeLeafEntryANSI, indexEntry: subtreeIndexEntryANSI, ansi: true}
	}
	return subnodeLayout{header: subtreeHeader, leafEntry: subtreeLeafEntry, indexEntry: subtreeIndexEntry}
}

func (l subnodeLayout) leaf(raw []byte, at int) (subnode, data, nested uint64) {
	if l.ansi {
		return uint64(leU32(raw, at)), uint64(leU32(raw, at+4)), uint64(leU32(raw, at+8))
	}
	return leU64(raw, at) & 0xFFFFFFFF, leU64(raw, at+8), leU64(raw, at+16)
}

func (l subnodeLayout) index(raw []byte, at int) uint64 {
	if l.ansi {
		return uint64(leU32(raw, at+4))
	}
	return leU64(raw, at+8)
}

// parseHeader parses the header for the layout its version names and counts
// checksum mismatches.
func parseHeader(bytes []byte, sourceLen uint64) (Header, uint64, error) {
	if len(bytes) < 10 {
		return Header{}, 0, corruptf("a PST header is at least 10 bytes, the source holds %d", len(bytes))
	}
	if bytes[0] != Signature[0] || bytes[1] != Signature[1] || bytes[2] != Signature[2] || bytes[3] != Signature[3] {
		return Header{}, 0, corruptf("the file signature is %02X, not !BDN", bytes[0:4])
	}
	var contentType StoreKind
	switch string(bytes[8:10]) {
	case MagicPST:
		contentType = StorePersonal
	case MagicOST:
		contentType = StoreOffline
	default:
		return Header{}, 0, corruptf("the content magic is %02X, not SM (PST) or SO (OST)", bytes[8:10])
	}
	version := leU16(bytes, 10)
	switch version {
	case 14, 15:
		return parseAnsiHeader(bytes, sourceLen, version, contentType)
	case 23:
		return parseUnicodeHeader(bytes, sourceLen, version, contentType, FormatUnicode512)
	case 36:
		return parseUnicodeHeader(bytes, sourceLen, version, contentType, FormatUnicode4K)
	case 21:
		return Header{}, 0, unsupportedf("PST version 21 (32-bit Unicode); this reader decodes versions 14/15 (ANSI), 23 (512-byte Unicode) and 36 (4 KiB Unicode)")
	case 37:
		return Header{}, 0, unsupportedf("WIP PST (version 37)")
	default:
		return Header{}, 0, unsupportedf("PST version %d; this reader decodes versions 14/15 (ANSI), 23 (512-byte Unicode) and 36 (4 KiB Unicode)", version)
	}
}

func checkCryptMethod(method byte) (CryptMethod, error) {
	switch CryptMethod(method) {
	case CryptNone, CryptPermute, CryptCyclic:
		return CryptMethod(method), nil
	case 0x10:
		return 0, unsupportedf("the WIP NDB crypt method 0x10 (WIP encryption)")
	default:
		return 0, unsupportedf("NDB crypt method 0x%02X (strong or unknown encryption); only none (0), compressible (1) and cyclic (2) are decoded", method)
	}
}

func parseAnsiHeader(bytes []byte, sourceLen uint64, version uint16, contentType StoreKind) (Header, uint64, error) {
	if len(bytes) < ansiHeaderBytes {
		return Header{}, 0, corruptf("an ANSI PST header is %d bytes, the source holds %d", ansiHeaderBytes, len(bytes))
	}
	if bytes[460] != 0x80 {
		return Header{}, 0, corruptf("the ANSI header sentinel is 0x%02X, not 0x80", bytes[460])
	}
	cryptMethod, err := checkCryptMethod(bytes[461])
	if err != nil {
		return Header{}, 0, err
	}
	var mismatches uint64
	if crc32PST(bytes[8:8+471]) != leU32(bytes, 4) {
		mismatches++
	}
	fileEOF := uint64(leU32(bytes, 168))
	if fileEOF > sourceLen {
		return Header{}, 0, corruptf("the header declares a %d-byte store, the source holds %d", fileEOF, sourceLen)
	}
	nodeRoot := Bref{BID: uint64(leU32(bytes, 184)), IB: uint64(leU32(bytes, 188))}
	blockRoot := Bref{BID: uint64(leU32(bytes, 192)), IB: uint64(leU32(bytes, 196))}
	if nodeRoot.BID == 0 || nodeRoot.IB == 0 || blockRoot.BID == 0 || blockRoot.IB == 0 {
		return Header{}, 0, corruptf("the header has an empty NBT or BBT root")
	}
	return Header{
		Version:       version,
		Format:        FormatAnsi,
		ContentType:   contentType,
		PageBytes:     pageBytes512,
		VersionClient: leU16(bytes, 12),
		CryptMethod:   cryptMethod,
		Unique:        leU32(bytes, 32),
		FileEOF:       fileEOF,
		BlockNext:     uint64(leU32(bytes, 24)),
		NodeRoot:      nodeRoot,
		BlockRoot:     blockRoot,
	}, mismatches, nil
}

func parseUnicodeHeader(bytes []byte, sourceLen uint64, version uint16, contentType StoreKind, format StoreFormat) (Header, uint64, error) {
	if len(bytes) < headerBytes {
		return Header{}, 0, corruptf("a Unicode PST header is %d bytes, the source holds %d", headerBytes, len(bytes))
	}
	if bytes[512] != 0x80 {
		return Header{}, 0, corruptf("the Unicode header sentinel is 0x%02X, not 0x80", bytes[512])
	}
	cryptMethod, err := checkCryptMethod(bytes[513])
	if err != nil {
		return Header{}, 0, err
	}
	var mismatches uint64
	if crc32PST(bytes[8:8+471]) != leU32(bytes, 4) {
		mismatches++
	}
	if crc32PST(bytes[8:8+516]) != leU32(bytes, 524) {
		mismatches++
	}
	fileEOF := leU64(bytes, 184)
	if fileEOF > sourceLen {
		return Header{}, 0, corruptf("the header declares a %d-byte store, the source holds %d", fileEOF, sourceLen)
	}
	nodeRoot := Bref{BID: leU64(bytes, 216), IB: leU64(bytes, 224)}
	blockRoot := Bref{BID: leU64(bytes, 232), IB: leU64(bytes, 240)}
	if nodeRoot.BID == 0 || nodeRoot.IB == 0 || blockRoot.BID == 0 || blockRoot.IB == 0 {
		return Header{}, 0, corruptf("the header has an empty NBT or BBT root")
	}
	return Header{
		Version:       version,
		Format:        format,
		ContentType:   contentType,
		PageBytes:     format.PageBytes(),
		VersionClient: leU16(bytes, 12),
		CryptMethod:   cryptMethod,
		Unique:        leU32(bytes, 40),
		FileEOF:       fileEOF,
		BlockNext:     leU64(bytes, 516),
		NodeRoot:      nodeRoot,
		BlockRoot:     blockRoot,
	}, mismatches, nil
}

// data_offset returns the file offset of the first external leaf block a data
// BID resolves to.
func (r *Reader) dataOffset(bid uint64, depth uint8) (uint64, bool) {
	if bid == 0 {
		return 0, false
	}
	if bid&bitInternal == 0 {
		reference, ok := r.blocks[bid&searchMask]
		if !ok {
			return 0, false
		}
		return reference.ib, true
	}
	if depth >= 2 {
		return 0, false
	}
	raw, err := r.readBlock(bid, false)
	if err != nil {
		return 0, false
	}
	parsed, err := parseArray(raw, bid, r.header.Format)
	if err != nil || len(parsed.bids) == 0 {
		return 0, false
	}
	return r.dataOffset(parsed.bids[0], depth+1)
}

func leU16(bytes []byte, at int) uint16 {
	return binary.LittleEndian.Uint16(bytes[at:])
}

func leU32(bytes []byte, at int) uint32 {
	return binary.LittleEndian.Uint32(bytes[at:])
}

func leU64(bytes []byte, at int) uint64 {
	return binary.LittleEndian.Uint64(bytes[at:])
}

// sha256Hex returns the lower-case hex SHA-256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
