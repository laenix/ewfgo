package pst

import (
	"fmt"
	"strings"
)

// Attachments returns the message's attachment table, one entry per row in
// row-matrix order.  present is false when the message has no attachment table
// at all, which is not an error: most messages never had one.
func (r *Reader) Attachments(nid uint64) (rows []Attachment, present bool, err error) {
	node := r.node(nid)
	if node == nil {
		return nil, false, corruptf("no node 0x%X in the NBT", nid)
	}
	return r.attachmentsOf(node)
}

func (r *Reader) attachmentsOf(node *Node) ([]Attachment, bool, error) {
	label := fmt.Sprintf("message node 0x%X", node.NID)
	messageTree, err := r.subnodeEntriesOf(node)
	if err != nil {
		return nil, false, err
	}
	table, ok := messageTree[AttachmentTableNID]
	if !ok {
		return nil, false, nil
	}
	tableLabel := "the attachment table of " + label
	tableTree, err := r.nestedTree(tableLabel, table)
	if err != nil {
		return nil, false, err
	}
	var blocks [][]byte
	if _, err := r.expandData(table.data, 0, &blocks); err != nil {
		return nil, false, err
	}
	context, err := readTableContext(blocks, hidLayoutForPageBytes(r.header.PageBytes))
	if err != nil {
		return nil, false, corruptf("%s: %v", tableLabel, err)
	}
	matrix, err := r.tableMatrix(tableLabel, context, tableTree)
	if err != nil {
		return nil, false, err
	}
	tableRows, err := context.rowsIn(matrix, r.limits.MaxTCRows, r.limits.MaxTCMatrixBytes)
	if err != nil {
		return nil, false, corruptf("%s: %v", tableLabel, err)
	}
	attachments := make([]Attachment, 0, len(tableRows))
	for index, row := range tableRows {
		attachment, err := r.attachment(label, index, &row, context, tableTree, messageTree)
		if err != nil {
			return nil, false, err
		}
		attachments = append(attachments, attachment)
	}
	return attachments, true, nil
}

func (r *Reader) tableMatrix(label string, context *tableContext, tree map[uint32]subnodeEntry) ([][]byte, error) {
	switch context.rows.kind {
	case rowMatrixEmpty:
		return nil, nil
	case rowMatrixHeap:
		return [][]byte{context.rows.bytes}, nil
	case rowMatrixSubnode:
		return r.subnodeBlocks(label, tree, context.rows.subnode)
	default:
		return nil, corruptf("%s: unknown row-matrix kind", label)
	}
}

func (r *Reader) attachment(messageLabel string, index int, row *tcRow, context *tableContext, tableTree, messageTree map[uint32]subnodeEntry) (Attachment, error) {
	objectLabel := fmt.Sprintf("attachment object 0x%X (row %d) of %s", row.id, index, messageLabel)
	entry, haveEntry := messageTree[row.id]
	var properties []Property
	var objectTree map[uint32]subnodeEntry
	var data *rawValue
	var dataProblem *string
	var objectBID, objectOffset uint64
	if haveEntry {
		tree, err := r.nestedTree(objectLabel, entry)
		if err != nil {
			return Attachment{}, err
		}
		objectTree = tree
		var blocks [][]byte
		if _, err := r.expandData(entry.data, 0, &blocks); err != nil {
			return Attachment{}, err
		}
		raw, err := r.readPCRaw(objectLabel, blocks)
		if err != nil {
			return Attachment{}, err
		}
		// The data property is kept unresolved so that a large value is
		// measured from its blocks instead of being loaded.
		rest := make([]rawProperty, 0, len(raw))
		for _, property := range raw {
			if property.id == propAttachData {
				value := property.value
				data = &value
			} else {
				rest = append(rest, property)
			}
		}
		properties, err = r.resolveProperties(objectLabel, rest, tree)
		if err != nil {
			return Attachment{}, err
		}
		objectBID = entry.data
		objectOffset, _ = r.dataOffset(entry.data, 0)
	} else {
		objectTree = map[uint32]subnodeEntry{}
		problem := fmt.Sprintf("%s: the message's subnode tree holds no object with that NID (%d entries)", objectLabel, len(messageTree))
		dataProblem = &problem
	}

	method := propUnsigned(properties, propAttachMethod)
	if method == nil {
		cellMethod, err := r.cellUnsigned(objectLabel, context, row, propAttachMethod)
		if err != nil {
			return Attachment{}, err
		}
		method = cellMethod
	}

	var dataBytes *uint64
	var digest *string
	var problem *string
	var embedded *EmbeddedMessage
	if data != nil {
		if method != nil && *method == 5 {
			message, err := r.embeddedMessage(objectLabel, *data, objectTree)
			if err != nil {
				text := "the embedded message: " + err.Error()
				problem = &text
			} else {
				embedded = &message
			}
		} else {
			switch data.kind {
			case rawHeap:
				length := uint64(len(data.bytes))
				dataBytes = &length
				if length > r.limits.MaxAttachmentHashBytes {
					text := fmt.Sprintf("the data is %d bytes, over the %d-byte hash limit", length, r.limits.MaxAttachmentHashBytes)
					problem = &text
				} else {
					value := sha256Hex(data.bytes)
					digest = &value
				}
			case rawSubnode:
				dataEntry, ok := objectTree[data.subnode]
				if !ok {
					text := fmt.Sprintf("the data property names subnode 0x%08X, which %s's subnode tree does not hold (%d entries)", data.subnode, objectLabel, len(objectTree))
					problem = &text
					break
				}
				length, err := r.dataLength(dataEntry.data, 0)
				if err != nil {
					text := "the data property's length: " + err.Error()
					problem = &text
					break
				}
				dataBytes = &length
				if length > r.limits.MaxAttachmentHashBytes {
					text := fmt.Sprintf("the data is %d bytes, over the %d-byte hash limit", length, r.limits.MaxAttachmentHashBytes)
					problem = &text
					break
				}
				bytes, err := r.subnodeData(objectLabel, objectTree, data.subnode)
				if err != nil {
					text := err.Error()
					problem = &text
					break
				}
				value := sha256Hex(bytes)
				digest = &value
			}
		}
	}
	if dataProblem == nil {
		dataProblem = problem
	}

	filename := firstString(
		propText(properties, propAttachLongFilename),
		propText(properties, propAttachFilename),
		propText(properties, propAttachDisplayName),
	)
	if filename == nil {
		value, err := r.cellText(objectLabel, tableTree, context, row, propAttachLongFilename)
		if err != nil {
			return Attachment{}, err
		}
		filename = value
	}
	if filename == nil {
		value, err := r.cellText(objectLabel, tableTree, context, row, propAttachFilename)
		if err != nil {
			return Attachment{}, err
		}
		filename = value
	}
	extension := propText(properties, propAttachExtension)
	if extension == nil {
		value, err := r.cellText(objectLabel, tableTree, context, row, propAttachExtension)
		if err != nil {
			return Attachment{}, err
		}
		extension = value
	}
	mimeType := propText(properties, propAttachMIME)
	if mimeType == nil {
		value, err := r.cellText(objectLabel, tableTree, context, row, propAttachMIME)
		if err != nil {
			return Attachment{}, err
		}
		mimeType = value
	}
	size := propUnsigned(properties, propAttachSize)
	if size == nil {
		value, err := r.cellUnsigned(objectLabel, context, row, propAttachSize)
		if err != nil {
			return Attachment{}, err
		}
		size = value
	}
	created := propTime(properties, propAttachCreationTime)
	if created == nil {
		value, err := r.cellFiletime(objectLabel, context, row, propAttachCreationTime)
		if err != nil {
			return Attachment{}, err
		}
		created = value
	}
	modified := propTime(properties, propAttachModificationTime)
	if modified == nil {
		value, err := r.cellFiletime(objectLabel, context, row, propAttachModificationTime)
		if err != nil {
			return Attachment{}, err
		}
		modified = value
	}
	path := firstString(
		propText(properties, propAttachLongPathname),
		propText(properties, propAttachPathname),
	)
	return Attachment{
		Index:        index,
		NID:          row.id,
		Filename:     filename,
		Extension:    extension,
		MIMEType:     mimeType,
		Method:       method,
		Size:         size,
		ContentID:    propText(properties, propAttachContentID),
		Path:         path,
		Created:      created,
		Modified:     modified,
		DataBytes:    dataBytes,
		SHA256:       digest,
		DataProblem:  dataProblem,
		Embedded:     embedded,
		ObjectBID:    objectBID,
		ObjectOffset: objectOffset,
	}, nil
}

func firstString(values ...*string) *string {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

// embeddedMessage reads the message a method-5 attachment embeds.
func (r *Reader) embeddedMessage(label string, value rawValue, tree map[uint32]subnodeEntry) (EmbeddedMessage, error) {
	var bytes []byte
	switch value.kind {
	case rawHeap:
		bytes = value.bytes
	case rawSubnode:
		stored, err := r.subnodeData(label, tree, value.subnode)
		if err != nil {
			return EmbeddedMessage{}, err
		}
		bytes = stored
	default:
		return EmbeddedMessage{}, corruptf("the data object has an unknown storage kind")
	}
	if len(bytes) < 4 {
		return EmbeddedMessage{}, corruptf("the data object is %d bytes, too short to name a message NID", len(bytes))
	}
	nid := leU32(bytes, 0)
	if nid&0x1F != uint32(nidTypeMessage) {
		return EmbeddedMessage{}, corruptf("the data object names NID 0x%08X, whose type 0x%X is not a message", nid, nid&0x1F)
	}
	entry, ok := tree[nid]
	if !ok {
		return EmbeddedMessage{}, corruptf("the data object names message NID 0x%08X, which %s's subnode tree does not hold (%d entries)", nid, label, len(tree))
	}
	var blocks [][]byte
	if _, err := r.expandData(entry.data, 0, &blocks); err != nil {
		return EmbeddedMessage{}, err
	}
	raw, err := r.readPCRaw(label, blocks)
	if err != nil {
		return EmbeddedMessage{}, err
	}
	nested := map[uint32]subnodeEntry{}
	if entry.nested != 0 {
		nested, err = r.subnodeTree(entry.nested)
		if err != nil {
			return EmbeddedMessage{}, err
		}
	}
	wanted := make([]rawProperty, 0, len(raw))
	for _, property := range raw {
		switch property.id {
		case propSubject, propSenderName, propSenderEmail, propSenderSMTP,
			propSenderSMTPAddress, propMessageClass, propClientSubmitTime,
			propDeliveryTime, propMessageSize, propInternetMessageID:
			wanted = append(wanted, property)
		}
	}
	properties, err := r.resolveProperties(label, wanted, nested)
	if err != nil {
		return EmbeddedMessage{}, err
	}
	senderEmail, senderSource := senderOf(properties)
	return EmbeddedMessage{
		NID:               nid,
		Subject:           propText(properties, propSubject),
		SenderName:        propText(properties, propSenderName),
		SenderEmail:       senderEmail,
		SenderEmailSource: senderSource,
		MessageClass:      propText(properties, propMessageClass),
		SubmitTime:        propTime(properties, propClientSubmitTime),
		DeliveryTime:      propTime(properties, propDeliveryTime),
		Size:              propUnsigned(properties, propMessageSize),
		MessageID:         propText(properties, propInternetMessageID),
	}, nil
}

// Recipients returns the message's recipient table, one entry per row in
// row-matrix order.  present is false when the message has no recipient
// table.
func (r *Reader) Recipients(nid uint64) (rows []Recipient, present bool, err error) {
	node := r.node(nid)
	if node == nil {
		return nil, false, corruptf("no node 0x%X in the NBT", nid)
	}
	return r.recipientsOf(node)
}

func (r *Reader) recipientsOf(node *Node) ([]Recipient, bool, error) {
	label := fmt.Sprintf("message node 0x%X", node.NID)
	messageTree, err := r.subnodeEntriesOf(node)
	if err != nil {
		return nil, false, err
	}
	table, ok := messageTree[RecipientTableNID]
	if !ok {
		return nil, false, nil
	}
	tableLabel := "the recipient table of " + label
	tableTree, err := r.nestedTree(tableLabel, table)
	if err != nil {
		return nil, false, err
	}
	var blocks [][]byte
	if _, err := r.expandData(table.data, 0, &blocks); err != nil {
		return nil, false, err
	}
	context, err := readTableContext(blocks, hidLayoutForPageBytes(r.header.PageBytes))
	if err != nil {
		return nil, false, corruptf("%s: %v", tableLabel, err)
	}
	matrix, err := r.tableMatrix(tableLabel, context, tableTree)
	if err != nil {
		return nil, false, err
	}
	tableRows, err := context.rowsIn(matrix, r.limits.MaxTCRows, r.limits.MaxTCMatrixBytes)
	if err != nil {
		return nil, false, corruptf("%s: %v", tableLabel, err)
	}
	recipients := make([]Recipient, 0, len(tableRows))
	for index, row := range tableRows {
		recipients = append(recipients, r.recipient(label, index, &row, context, tableTree))
	}
	return recipients, true, nil
}

func (r *Reader) recipient(messageLabel string, index int, row *tcRow, context *tableContext, tableTree map[uint32]subnodeEntry) Recipient {
	label := fmt.Sprintf("recipient row %d of %s", index, messageLabel)
	var problem *string
	record := func(err error) {
		if problem == nil {
			text := err.Error()
			problem = &text
		}
	}
	readText := func(id uint16) *string {
		value, err := r.cellText(label, tableTree, context, row, id)
		if err != nil {
			record(err)
			return nil
		}
		return value
	}
	recipient := Recipient{
		Index:       index,
		RowID:       row.id,
		DisplayName: readText(propDisplayName),
		AddressType: readText(propAddressType),
		Email:       readText(propEmailAddress),
		SMTP:        readText(propSenderSMTP),
	}
	kind, err := r.cellUnsigned(label, context, row, propRecipientType)
	if err != nil {
		record(err)
	} else {
		recipient.Kind = kind
	}
	recipient.Problem = problem
	return recipient
}

// cellText reads a string cell of one table row.
func (r *Reader) cellText(label string, tree map[uint32]subnodeEntry, context *tableContext, row *tcRow, id uint16) (*string, error) {
	column, ok := rowColumn(context, id)
	if !ok {
		return nil, nil
	}
	kind := context.columns[column].kind()
	cell, ok := rowCell(row, column)
	if !ok || cell.kind == tcValueAbsent {
		return nil, nil
	}
	var bytes []byte
	switch cell.kind {
	case tcValueBytes:
		bytes = cell.bytes
	case tcValueSubnode:
		resolved, err := r.subnodeData(label, tree, cell.subnode)
		if err != nil {
			return nil, err
		}
		bytes = resolved
	default:
		return nil, nil
	}
	// A table row carries no code page of its own; the owning message's
	// declaration is not attributed to it, so a byte string here is preserved
	// one-to-one unless the store is Unicode.
	text := textContext{ansi: r.header.Format.IsAnsi()}
	property, err := parseProperty(id, kind, bytes, text, r.limits.MaxMultiValues)
	if err != nil {
		return nil, err
	}
	switch property.Value.Kind {
	case ValueString:
		value := property.Value.String
		return &value, nil
	case ValueMultiString:
		value := joinStrings(property.Value.MultiString, "; ")
		return &value, nil
	default:
		return nil, unsupportedf("column 0x%04X typed 0x%04X is not a string", id, property.Kind)
	}
}

func joinStrings(items []string, separator string) string {
	return strings.Join(items, separator)
}

// cellUnsigned reads an unsigned integer cell of one table row.
func (r *Reader) cellUnsigned(label string, context *tableContext, row *tcRow, id uint16) (*uint32, error) {
	column, ok := rowColumn(context, id)
	if !ok {
		return nil, nil
	}
	cell, ok := rowCell(row, column)
	if !ok || cell.kind == tcValueAbsent {
		return nil, nil
	}
	var bytes []byte
	switch cell.kind {
	case tcValueBytes:
		bytes = cell.bytes
	case tcValueSubnode:
		return nil, unsupportedf("column 0x%04X of %s is variable width (subnode 0x%08X); an integer column is stored in the row", id, label, cell.subnode)
	default:
		return nil, nil
	}
	var value uint32
	switch len(bytes) {
	case 2:
		value = uint32(leU16(bytes, 0))
	case 4:
		value = leU32(bytes, 0)
	default:
		return nil, corruptf("column 0x%04X of %s holds %d bytes; an integer is 2 or 4", id, label, len(bytes))
	}
	return &value, nil
}

// cellFiletime reads a FILETIME cell of one table row.
func (r *Reader) cellFiletime(label string, context *tableContext, row *tcRow, id uint16) (*Filetime, error) {
	column, ok := rowColumn(context, id)
	if !ok {
		return nil, nil
	}
	cell, ok := rowCell(row, column)
	if !ok || cell.kind == tcValueAbsent {
		return nil, nil
	}
	var bytes []byte
	switch cell.kind {
	case tcValueBytes:
		bytes = cell.bytes
	case tcValueSubnode:
		return nil, unsupportedf("column 0x%04X of %s is variable width (subnode 0x%08X); a time column is stored in the row", id, label, cell.subnode)
	default:
		return nil, nil
	}
	if len(bytes) != 8 {
		return nil, corruptf("column 0x%04X of %s holds %d bytes; a FILETIME is 8", id, label, len(bytes))
	}
	value := Filetime(leU64(bytes, 0))
	return &value, nil
}

// rowColumn returns the index of the column carrying property id.
func rowColumn(context *tableContext, id uint16) (int, bool) {
	for index := range context.columns {
		if context.columns[index].id() == id {
			return index, true
		}
	}
	return 0, false
}

// rowCell returns one column's cell, or nil when its existence bit is clear.
func rowCell(row *tcRow, column int) (*tcValue, bool) {
	for index := range row.cells {
		if row.cells[index].column == column {
			return &row.cells[index].value, true
		}
	}
	return nil, false
}

// SearchFolders returns every reachable search folder (NID type 3).
func (r *Reader) SearchFolders() ([]SearchFolder, error) {
	reachable := r.reachableNIDs()
	folders := make([]SearchFolder, 0)
	for index := range r.nodes {
		node := &r.nodes[index]
		if node.Kind() != nidTypeSearchFolder || !isReachable(reachable, node.NID) {
			continue
		}
		folder, err := r.searchFolderOf(node)
		if err != nil {
			return nil, err
		}
		folders = append(folders, folder)
		if len(folders) > r.limits.MaxItems {
			return nil, limitf("the store holds more than %d reachable search folders", r.limits.MaxItems)
		}
	}
	return folders, nil
}

func (r *Reader) searchFolderOf(node *Node) (SearchFolder, error) {
	properties, err := r.propertiesOf(node)
	if err != nil {
		return SearchFolder{}, err
	}
	folder := SearchFolder{
		NID:        node.NID,
		Name:       propText(properties, propDisplayName),
		FolderType: propUnsigned(properties, propFolderType),
	}

	// The criteria object is a sibling, not a child, of the folder node.
	criteriaNID := siblingNID(node.NID, nidTypeSearchCriteria)
	var criteria []Property
	if r.node(criteriaNID) != nil {
		read, err := r.Properties(criteriaNID)
		if err != nil {
			text := err.Error()
			folder.CriteriaProblem = &text
		} else {
			criteria = read
		}
	}
	// The criteria object is authoritative where both carry a property; some
	// writers keep the definition on the folder object instead, so the folder
	// is the fallback.
	number := func(id uint16) *uint32 {
		if value := propUnsigned(criteria, id); value != nil {
			return value
		}
		return propUnsigned(properties, id)
	}
	bytesOf := func(id uint16) []byte {
		if value := propBinary(criteria, id); value != nil {
			return value
		}
		return propBinary(properties, id)
	}
	folder.FolderType = orUint32(number(propFolderType), folder.FolderType)
	folder.TemplateID = number(propSearchFolderTemplateID)
	folder.StorageType = number(propSearchFolderStorageType)
	folder.Tag = number(propSearchFolderTag)
	folder.EFPFlags = number(propSearchFolderEFPFlags)
	folder.LastUsed = propTime(criteria, propSearchFolderLastUsed)
	if folder.LastUsed == nil {
		folder.LastUsed = propTime(properties, propSearchFolderLastUsed)
	}
	folder.FolderID = bytesOf(propSearchFolderID)
	folder.Definition = bytesOf(propSearchFolderDefinition)

	// The contents table also shares the folder's index.
	tableNID := siblingNID(node.NID, nidTypeSearchContents)
	if r.node(tableNID) != nil {
		links, err := r.searchLinks(tableNID)
		if err != nil {
			text := err.Error()
			folder.TableProblem = &text
		} else {
			folder.Links = links
		}
	} else {
		text := fmt.Sprintf("the search folder has no contents table (NID 0x%X)", tableNID)
		folder.TableProblem = &text
	}
	return folder, nil
}

func orUint32(value, fallback *uint32) *uint32 {
	if value != nil {
		return value
	}
	return fallback
}

// searchLinks returns the rows of a search contents table.
func (r *Reader) searchLinks(nid uint64) ([]SearchLink, error) {
	label := fmt.Sprintf("the search contents table 0x%X", nid)
	blocks, err := r.NodeBlocks(nid)
	if err != nil {
		return nil, err
	}
	if len(blocks) == 0 {
		return nil, corruptf("%s has no data blocks", label)
	}
	tree, err := r.subnodeEntries(nid)
	if err != nil {
		return nil, err
	}
	context, err := readTableContext(blocks, hidLayoutForPageBytes(r.header.PageBytes))
	if err != nil {
		return nil, corruptf("%s: %v", label, err)
	}
	matrix, err := r.tableMatrix(label, context, tree)
	if err != nil {
		return nil, err
	}
	rows, err := context.rowsIn(matrix, r.limits.MaxTCRows, r.limits.MaxTCMatrixBytes)
	if err != nil {
		return nil, corruptf("%s: %v", label, err)
	}
	links := make([]SearchLink, 0, len(rows))
	for _, row := range rows {
		parent, err := r.cellUnsigned(label, context, &row, propLTPParentNID)
		link := SearchLink{MessageNID: row.id, ParentNID: parent}
		if err != nil {
			text := err.Error()
			link.Problem = &text
		}
		links = append(links, link)
	}
	return links, nil
}
