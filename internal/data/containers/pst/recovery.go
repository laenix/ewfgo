package pst

import (
	"fmt"
	"sort"
)

// RecoverDeleted recovers messages the live folder tree does not reach.
//
// Four places are examined, and each recovered item says which one it came
// from:
//
//   - descriptors left in NBT leaf-page slots past the live count
//     (RecoveryFreeNode);
//   - live NBT message nodes whose parent chain does not reach the root folder
//     (RecoveryOrphanNode);
//   - live BBT blocks no node or subnode tree references, whose bytes still
//     form a message property context (RecoveryOrphanBlock);
//   - descriptors left in BBT leaf-page slots past the live count, whose
//     blocks still decode (RecoveryFreeBlock).
//
// A candidate that names unreadable bytes, or whose heap or property context
// fails structural validation, is returned in Recovery.Refusals instead of
// being guessed into fields.  A valid property context with no message
// property at all is ignored: it may be an attachment object, a table or a
// folder, not a deleted message.  Allocated folders and messages are never
// included: a store with no root folder returns an empty scan and a problem,
// because reachability cannot be established.
func (r *Reader) RecoverDeleted() (Recovery, error) {
	recovery := Recovery{}
	reachable := r.reachableNIDs()
	if reachable == nil {
		recovery.Problems = append(recovery.Problems, "the store has no root folder 0x22, so reachability from the folder tree could not be established")
		return recovery, nil
	}
	parents := r.parentNames()
	liveNIDs := make(map[uint64]struct{}, len(r.nodes))
	for _, node := range r.nodes {
		liveNIDs[node.NID] = struct{}{}
	}
	seenOffsets := make(map[uint64]struct{})

	// A live node the folder chain cannot reach: its block is allocated, but
	// it is not an allocated folder item.
	for index := range r.nodes {
		node := &r.nodes[index]
		if !(node.IsMessage() || node.IsAssociatedMessage()) {
			continue
		}
		if _, ok := reachable[node.NID]; ok {
			continue
		}
		candidate := fmt.Sprintf("NBT node 0x%X (data BID 0x%X)", node.NID, node.Data&searchMask)
		offset, hasOffset := r.nodeOffset(node)
		item, err := r.deletedFromNode(node, RecoveryOrphanNode, parents)
		if err != nil {
			recovery.Refusals = append(recovery.Refusals, Refusal{Candidate: candidate, Offset: optionalU64(offset, hasOffset), Reason: err.Error()})
			continue
		}
		if item != nil {
			if item.Offset != nil {
				seenOffsets[*item.Offset] = struct{}{}
			}
			recovery.Messages = append(recovery.Messages, *item)
		}
	}

	// A descriptor left in an unused NBT slot.  The live tree does not name
	// it, but the block B-tree may still allocate its data.
	for index := range r.freeNodes {
		node := &r.freeNodes[index]
		if _, live := liveNIDs[node.NID]; live {
			continue
		}
		if !(node.IsMessage() || node.IsAssociatedMessage()) {
			continue
		}
		candidate := fmt.Sprintf("free NBT slot node 0x%X (data BID 0x%X)", node.NID, node.Data&searchMask)
		offset, hasOffset := r.dataOffset(node.Data, 0)
		if _, allocated := r.blocks[node.Data&searchMask]; !allocated {
			reason := fmt.Sprintf("the descriptor names data BID 0x%X, which the live block B-tree does not allocate", node.Data&searchMask)
			recovery.Refusals = append(recovery.Refusals, Refusal{Candidate: candidate, Offset: optionalU64(offset, hasOffset), Reason: reason})
			continue
		}
		item, err := r.deletedFromNode(node, RecoveryFreeNode, parents)
		if err != nil {
			recovery.Refusals = append(recovery.Refusals, Refusal{Candidate: candidate, Offset: optionalU64(offset, hasOffset), Reason: err.Error()})
			continue
		}
		if item != nil {
			if item.Offset != nil {
				seenOffsets[*item.Offset] = struct{}{}
			}
			recovery.Messages = append(recovery.Messages, *item)
		}
	}

	// Allocated blocks no descriptor or subnode tree references.  The
	// reference walk has to succeed first: a tree it could not read would
	// turn live subnode data into false deleted items.
	referenced, complete := r.referencedBlocks()
	if !complete {
		recovery.Problems = append(recovery.Problems, "the block reference walk was incomplete (a node's data array or subnode tree could not be read), so unreferenced allocated blocks were not scanned")
	} else {
		orphans := make([]blockRef, 0)
		for _, reference := range r.blocks {
			if reference.bid&bitInternal != 0 {
				continue
			}
			if _, used := referenced[reference.bid&searchMask]; used {
				continue
			}
			orphans = append(orphans, reference)
		}
		sort.Slice(orphans, func(i, j int) bool { return orphans[i].ib < orphans[j].ib })
		for _, reference := range orphans {
			if _, seen := seenOffsets[reference.ib]; seen {
				continue
			}
			// The block descriptor itself has to validate before its contents
			// can be treated as a record; a corrupt trailer is not evidence of
			// a deleted message.
			data, err := r.decodeBlock(reference, true)
			if err != nil {
				continue
			}
			if !looksLikePC(data) {
				continue
			}
			candidate := fmt.Sprintf("orphaned allocated block BID 0x%X at offset %d", reference.bid&searchMask, reference.ib)
			item, err := r.deletedFromBlockBytes(data, reference.ib, RecoveryOrphanBlock)
			if err != nil {
				recovery.Refusals = append(recovery.Refusals, Refusal{Candidate: candidate, Offset: optionalU64(reference.ib, true), Reason: err.Error()})
				continue
			}
			if item != nil {
				seenOffsets[reference.ib] = struct{}{}
				recovery.Messages = append(recovery.Messages, *item)
			}
		}
	}

	// Descriptors left in unused BBT slots.  These blocks are not in the live
	// allocation map, so the descriptor is their only locator.
	for index := range r.freeBlocks {
		reference := r.freeBlocks[index]
		if reference.bid&bitInternal != 0 {
			continue
		}
		if _, seen := seenOffsets[reference.ib]; seen {
			continue
		}
		data, err := r.decodeBlock(reference, true)
		if err != nil {
			continue
		}
		if !looksLikePC(data) {
			continue
		}
		candidate := fmt.Sprintf("free BBT slot BID 0x%X at offset %d", reference.bid&searchMask, reference.ib)
		item, err := r.deletedFromBlockBytes(data, reference.ib, RecoveryFreeBlock)
		if err != nil {
			recovery.Refusals = append(recovery.Refusals, Refusal{Candidate: candidate, Offset: optionalU64(reference.ib, true), Reason: err.Error()})
			continue
		}
		if item != nil {
			seenOffsets[reference.ib] = struct{}{}
			recovery.Messages = append(recovery.Messages, *item)
		}
	}
	return recovery, nil
}

func optionalU64(value uint64, ok bool) *uint64 {
	if !ok {
		return nil
	}
	copy := value
	return &copy
}

func optionalU32(value uint32) *uint32 {
	copy := value
	return &copy
}

func optionalInt(value int) *int {
	copy := value
	return &copy
}

// parentNames returns names of every folder descriptor, live or free, so a
// recovered message's deleted parent can still be named when its property
// context survived.
func (r *Reader) parentNames() map[uint64]*string {
	names := make(map[uint64]*string)
	visit := func(node *Node) {
		if !node.IsFolder() {
			return
		}
		if _, exists := names[node.NID]; exists {
			return
		}
		properties, err := r.propertiesOf(node)
		if err != nil {
			names[node.NID] = nil
			return
		}
		names[node.NID] = propText(properties, propDisplayName)
	}
	for index := range r.nodes {
		visit(&r.nodes[index])
	}
	for index := range r.freeNodes {
		visit(&r.freeNodes[index])
	}
	return names
}

func (r *Reader) deletedFromNode(node *Node, recovery RecoveryKind, parents map[uint64]*string) (*DeletedMessage, error) {
	properties, err := r.propertiesOf(node)
	if err != nil {
		return nil, err
	}
	if !looksLikeMessage(properties) {
		return nil, nil
	}
	var attachmentCount *int
	if rows, present, err := r.attachmentsOf(node); err == nil {
		count := 0
		if present {
			count = len(rows)
		}
		attachmentCount = optionalInt(count)
	}
	var recipientCount *int
	if rows, present, err := r.recipientsOf(node); err == nil {
		count := 0
		if present {
			count = len(rows)
		}
		recipientCount = optionalInt(count)
	}
	var parent *uint64
	if node.Parent != 0 {
		value := uint64(node.Parent)
		parent = &value
	}
	var parentName *string
	if parent != nil {
		parentName = parents[*parent]
	}
	offset, hasOffset := r.nodeOffset(node)
	item := r.deletedFromProperties(
		optionalU64(node.NID, true),
		recovery,
		optionalU64(offset, hasOffset),
		parent,
		parentName,
		node.IsAssociatedMessage(),
		properties,
		attachmentCount,
		recipientCount,
	)
	return &item, nil
}

func (r *Reader) deletedFromBlockBytes(data []byte, offset uint64, recovery RecoveryKind) (*DeletedMessage, error) {
	properties, err := r.propertiesFromBlock(fmt.Sprintf("the block at offset %d", offset), data)
	if err != nil {
		return nil, err
	}
	if !looksLikeMessage(properties) {
		return nil, nil
	}
	item := r.deletedFromProperties(
		nil,
		recovery,
		optionalU64(offset, true),
		nil,
		nil,
		false,
		properties,
		nil,
		nil,
	)
	return &item, nil
}

func (r *Reader) deletedFromProperties(
	nid *uint64,
	recovery RecoveryKind,
	offset *uint64,
	parent *uint64,
	parentName *string,
	associated bool,
	properties []Property,
	attachmentCount *int,
	recipientCount *int,
) DeletedMessage {
	senderEmail, senderSource := senderOf(properties)
	message := DeletedMessage{
		NID:               nid,
		Recovery:          recovery,
		Offset:            offset,
		Parent:            parent,
		ParentName:        parentName,
		Associated:        associated,
		Subject:           propText(properties, propSubject),
		SenderName:        propText(properties, propSenderName),
		SenderEmail:       senderEmail,
		SenderEmailSource: senderSource,
		MessageClass:      propText(properties, propMessageClass),
		SubmitTime:        propTime(properties, propClientSubmitTime),
		DeliveryTime:      propTime(properties, propDeliveryTime),
		ModificationTime:  propTime(properties, propLastModificationTime),
		BodyBytes:         propertyLen(properties, propBody),
		BodyStream:        valueOf(properties, propBody) != nil,
		HTMLBytes:         propertyLen(properties, propHTML),
		RTFStreamBytes:    propertyLen(properties, propRTFCompressed),
		HasAttachments:    propBool(properties, propHasAttachments),
		AttachmentCount:   attachmentCount,
		RecipientCount:    recipientCount,
		DisplayTo:         displayList(properties, propDisplayTo),
		DisplayCc:         displayList(properties, propDisplayCc),
		DisplayBcc:        displayList(properties, propDisplayBcc),
	}
	if size := propI4(properties, propMessageSize); size != nil && *size >= 0 {
		message.Size = optionalU32(uint32(*size))
	}
	return message
}

// referencedBlocks returns the block IDs every live or free node references,
// directly or through a data array or subnode tree.  false means some
// reference could not be followed, so the set must not be used to call blocks
// orphaned.
func (r *Reader) referencedBlocks() (map[uint64]struct{}, bool) {
	referenced := make(map[uint64]struct{})
	visitedSubnodes := make(map[uint64]struct{})
	complete := true
	visit := func(node *Node) {
		if node.Data != 0 {
			r.referenceData(node.Data, 0, referenced, &complete)
		}
		if node.Subnode != 0 {
			r.referenceSubnodeTree(node.Subnode, 0, referenced, &complete, visitedSubnodes)
		}
	}
	for index := range r.nodes {
		visit(&r.nodes[index])
	}
	for index := range r.freeNodes {
		visit(&r.freeNodes[index])
	}
	return referenced, complete
}

func (r *Reader) referenceData(bid uint64, depth uint8, referenced map[uint64]struct{}, complete *bool) {
	key := bid & searchMask
	if _, seen := referenced[key]; seen {
		if bid&bitInternal != 0 {
			// A repeated array means the reference walk is not a tree.
			*complete = false
		}
		return
	}
	referenced[key] = struct{}{}
	if bid&bitInternal == 0 {
		return
	}
	if depth >= 2 {
		*complete = false
		return
	}
	raw, err := r.readBlock(bid, false)
	if err != nil {
		*complete = false
		return
	}
	parsed, err := parseArray(raw, bid, r.header.Format)
	if err != nil {
		*complete = false
		return
	}
	for _, child := range parsed.bids {
		r.referenceData(child, depth+1, referenced, complete)
	}
}

func (r *Reader) referenceSubnodeTree(bid uint64, depth uint8, referenced map[uint64]struct{}, complete *bool, visited map[uint64]struct{}) {
	key := bid & searchMask
	if _, seen := visited[key]; seen {
		// The subnode pages form a cycle, so no block can be called orphaned
		// on the strength of this walk.
		*complete = false
		return
	}
	visited[key] = struct{}{}
	referenced[key] = struct{}{}
	if depth > maxSubnodeLevels {
		*complete = false
		return
	}
	layout := subnodeLayoutForFormat(r.header.Format)
	raw, err := r.readBlock(bid, true)
	if err != nil {
		*complete = false
		return
	}
	if len(raw) < layout.header || raw[0] != subtreePageType {
		*complete = false
		return
	}
	level := raw[1]
	count := int(leU16(raw, 2))
	entry := layout.leafEntry
	if level != 0 {
		entry = layout.indexEntry
	}
	if entry <= 0 || count > (len(raw)-layout.header)/entry {
		*complete = false
		return
	}
	for index := 0; index < count; index++ {
		at := layout.header + index*entry
		if level == 0 {
			_, data, nested := layout.leaf(raw, at)
			if data == 0 {
				*complete = false
				continue
			}
			r.referenceData(data, 0, referenced, complete)
			if nested != 0 {
				r.referenceSubnodeTree(nested, depth+1, referenced, complete, visited)
			}
		} else {
			child := layout.index(raw, at)
			if child == 0 {
				*complete = false
				continue
			}
			r.referenceSubnodeTree(child, depth+1, referenced, complete, visited)
		}
	}
}

// nodeOffset returns the file offset of the first external leaf block a node's
// data BID resolves to.
func (r *Reader) nodeOffset(node *Node) (uint64, bool) {
	return r.dataOffset(node.Data, 0)
}

// looksLikePC reports whether a block starts like a property context heap: the
// heap signature at byte 2 and the PC client signature at byte 3.
func looksLikePC(data []byte) bool {
	return len(data) >= 4 && data[2] == hnSignature && data[3] == pcClient
}

// looksLikeMessage reports whether a property set carries at least one
// property a message must have.  A valid property context without any of
// these is a folder, a table row, an attachment object or something else.
func looksLikeMessage(properties []Property) bool {
	for _, property := range properties {
		switch property.ID {
		case propSubject, propMessageClass, propClientSubmitTime, propDeliveryTime,
			propLastModificationTime, propSenderName, propSenderEmail,
			propSenderSMTPAddress, propMessageSize, propBody, propHTML,
			propRTFCompressed:
			return true
		}
	}
	return false
}
