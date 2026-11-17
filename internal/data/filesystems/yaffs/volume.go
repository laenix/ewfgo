package yaffs

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Detect reports whether src carries a YAFFS2 tag pattern and root header.
func Detect(src source.ByteSource) (bool, error) {
	layout, err := DetectLayout(src)
	return layout != nil, err
}

// DetectLayout returns the page geometry that proves src is YAFFS2, or nil
// when no tried geometry shows a root header and enough plausible tags.
func DetectLayout(src source.ByteSource) (*Layout, error) {
	length := src.Len()
	for index := range Layouts {
		layout := Layouts[index]
		pages, ok := layout.Pages(length)
		if !ok || pages == 0 {
			continue
		}
		evidence, err := scanEvidence(src, layout, pages)
		if err != nil {
			return nil, err
		}
		if evidence.root && evidence.plausible >= minPlausibleTags {
			found := layout
			return &found, nil
		}
	}
	return nil, nil
}

type evidence struct {
	plausible uint64
	root      bool
}

func batchPages(layout Layout) uint64 {
	count := uint64(scanBatchBytes / layout.Stride)
	if count == 0 {
		count = 1
	}
	return count
}

func batchBytes(layout Layout) int {
	return int(batchPages(layout)) * layout.Stride
}

func scanEvidence(src source.ByteSource, layout Layout, pages uint64) (evidence, error) {
	var out evidence
	limit := pages
	if limit > detectPages {
		limit = detectPages
	}
	if limit == 0 {
		return out, nil
	}
	batch := make([]byte, batchBytes(layout))
	page := make([]byte, layout.PageData)
	var first uint64
	for first < limit {
		count := limit - first
		if count > batchPages(layout) {
			count = batchPages(layout)
		}
		bytes := int(count) * layout.Stride
		offset := first * uint64(layout.Stride)
		if err := readAt(src, offset, batch[:bytes]); err != nil {
			return out, err
		}
		for index := 0; index < int(count); index++ {
			base := index * layout.Stride
			raw := batch[base+layout.TagOffset : base+layout.TagOffset+TagBytes]
			if allErased(raw) {
				continue
			}
			tag, ok := ParseTag(raw, layout.PageData)
			if !ok {
				continue
			}
			out.plausible++
			if tag.Chunk == 0 {
				pageOffset := (first + uint64(index)) * uint64(layout.Stride)
				if err := readAt(src, pageOffset, page); err != nil {
					return out, err
				}
				if tag.Object == RootObjectID {
					if header, ok := ParseHeader(page); ok &&
						header.Kind.IsDirectory() && header.Name == "/" {
						out.root = true
					}
				}
			}
		}
		first += count
	}
	return out, nil
}

func allErased(bytes []byte) bool {
	for _, value := range bytes {
		if value != 0xff {
			return false
		}
	}
	return true
}

type scanResult struct {
	objects            map[uint32]*rawObject
	pages              uint64
	tags               uint64
	undecodableTags    uint64
	headers            uint64
	undecodableHeaders uint64
	chunkEntries       int
}

func scanAll(src source.ByteSource, layout Layout) (*scanResult, error) {
	pages, ok := layout.Pages(src.Len())
	if !ok {
		return nil, corruptf("the image is not a whole number of %d-byte pages", layout.Stride)
	}
	if pages == 0 {
		return nil, corruptf("the image holds no pages")
	}
	result := &scanResult{
		objects: make(map[uint32]*rawObject),
		pages:   pages,
	}
	batch := make([]byte, batchBytes(layout))
	page := make([]byte, layout.PageData)
	var first uint64
	for first < pages {
		count := pages - first
		if count > batchPages(layout) {
			count = batchPages(layout)
		}
		bytes := int(count) * layout.Stride
		if err := readAt(src, first*uint64(layout.Stride), batch[:bytes]); err != nil {
			return nil, err
		}
		for index := 0; index < int(count); index++ {
			base := index * layout.Stride
			raw := batch[base+layout.TagOffset : base+layout.TagOffset+TagBytes]
			if allErased(raw) {
				continue
			}
			tag, ok := ParseTag(raw, layout.PageData)
			if !ok {
				result.undecodableTags++
				continue
			}
			if _, found := result.objects[tag.Object]; !found &&
				len(result.objects) >= MaxObjects {
				return nil, limitf("more than %d objects were found", MaxObjects)
			}
			pageIndex := first + uint64(index)
			object := result.objects[tag.Object]
			if object == nil {
				object = &rawObject{chunks: make(map[uint32]tagOccurrence)}
				result.objects[tag.Object] = object
			}
			result.tags++
			if tag.Chunk == 0 {
				if err := readAt(src, pageIndex*uint64(layout.Stride), page); err != nil {
					return nil, err
				}
				if header, ok := ParseHeader(page); ok {
					object.pushHeader(headerOccurrence{
						serial: tag.Serial,
						page:   pageIndex,
						header: header,
					})
					result.headers++
				} else {
					result.undecodableHeaders++
				}
				continue
			}
			if object.pushChunk(tag.Chunk, tagOccurrence{
				serial: tag.Serial,
				page:   pageIndex,
				bytes:  tag.Bytes,
			}) {
				result.chunkEntries++
				if result.chunkEntries > MaxChunkEntries {
					return nil, limitf("more than %d chunk records were found", MaxChunkEntries)
				}
			}
		}
		first += count
	}
	return result, nil
}

type objectData struct {
	header Header
	chunks map[uint32]tagOccurrence
}

// Volume is an opened YAFFS2 image.
type Volume struct {
	source source.ByteSource
	layout Layout

	pages    uint64
	tags     uint64
	objects  map[uint32]objectData
	entries  []Entry
	byPath   map[string]int
	byRecord map[uint64]int
	children map[string][]int

	headers            uint64
	chunks             uint64
	undecodableTags    uint64
	undecodableHeaders uint64
	unresolvedDeleted  uint64

	fileID atomic.Uint64
}

// Open detects and mounts a YAFFS2 image.
func Open(src source.ByteSource) (*Volume, error) {
	layout, err := DetectLayout(src)
	if err != nil {
		return nil, err
	}
	if layout == nil {
		return nil, unsupportedf("the image has no YAFFS2 tag pattern or no root object header")
	}
	scan, err := scanAll(src, *layout)
	if err != nil {
		return nil, err
	}
	volume := &Volume{
		source:             src,
		layout:             *layout,
		pages:              scan.pages,
		tags:               scan.tags,
		objects:            make(map[uint32]objectData),
		byPath:             make(map[string]int),
		byRecord:           make(map[uint64]int),
		children:           make(map[string][]int),
		headers:            scan.headers,
		undecodableTags:    scan.undecodableTags,
		undecodableHeaders: scan.undecodableHeaders,
	}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	for _, object := range scan.objects {
		volume.chunks += uint64(len(object.chunks))
	}
	if err := volume.walk(scan.objects); err != nil {
		return nil, err
	}
	return volume, nil
}

// Layout returns the page geometry the image was mounted with.
func (v *Volume) Layout() Layout { return v.layout }

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Pages returns the number of whole pages scanned.
func (v *Volume) Pages() uint64 { return v.pages }

// Tags returns the number of plausible tags decoded.
func (v *Volume) Tags() uint64 { return v.tags }

// Unreadable returns tags and headers that did not decode.
func (v *Volume) Unreadable() uint64 {
	return v.undecodableTags + v.undecodableHeaders
}

// UnresolvedDeleted returns deleted objects whose shadow no longer names a
// reachable live directory.
func (v *Volume) UnresolvedDeleted() uint64 { return v.unresolvedDeleted }

// Entries returns every listed object, live and deleted, in walk order.
func (v *Volume) Entries() []Entry {
	out := make([]Entry, len(v.entries))
	copy(out, v.entries)
	return out
}

// Nodes is an alias for Entries.
func (v *Volume) Nodes() []Entry { return v.Entries() }

// Info returns the volume report.
func (v *Volume) Info() Info {
	return Info{
		Kind:              KindLabel,
		PageSize:          v.layout.PageData,
		TagSize:           TagBytes,
		Stride:            v.layout.Stride,
		Pages:             v.pages,
		Tags:              v.tags,
		Objects:           uint64(len(v.objects)),
		Headers:           v.headers,
		Chunks:            v.chunks,
		Entries:           uint64(len(v.entries)),
		UnreadableTags:    v.undecodableTags,
		UnreadableHeaders: v.undecodableHeaders,
		UnresolvedDeleted: v.unresolvedDeleted,
		LostFound:         v.hasRecord(uint64(LostFoundObjectID)),
	}
}

// Facts returns the reference reader's key/value report.
func (v *Volume) Facts() [][2]string {
	info := v.Info()
	return [][2]string{
		{"type", info.Kind},
		{"entries", fmt.Sprint(info.Entries)},
		{"page_size", fmt.Sprint(info.PageSize)},
		{"tag_size", fmt.Sprint(info.TagSize)},
		{"stride", fmt.Sprint(info.Stride)},
		{"pages", fmt.Sprint(info.Pages)},
		{"tags", fmt.Sprint(info.Tags)},
		{"objects", fmt.Sprint(info.Objects)},
		{"headers", fmt.Sprint(info.Headers)},
		{"chunks", fmt.Sprint(info.Chunks)},
		{"unreadable_tags", fmt.Sprint(info.UnreadableTags)},
		{"unreadable_headers", fmt.Sprint(info.UnreadableHeaders)},
		{"unresolved_deleted", fmt.Sprint(info.UnresolvedDeleted)},
		{"lost_found", fmt.Sprint(info.LostFound)},
	}
}

func (v *Volume) hasRecord(record uint64) bool {
	_, found := v.byRecord[record]
	return found
}

func cleanPath(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	parts := make([]string, 0, 8)
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." {
			continue
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

func pathName(path string) string {
	path = cleanPath(path)
	if path == "/" {
		return "/"
	}
	if at := strings.LastIndexByte(path, '/'); at >= 0 {
		return path[at+1:]
	}
	return path
}

func joinPath(parent, name string) string {
	if parent == "/" {
		return "/" + name
	}
	return parent + "/" + name
}

func (v *Volume) walk(raw map[uint32]*rawObject) error {
	current := make(map[uint32]Header)
	previous := make(map[uint32]Header)
	for id, object := range raw {
		if len(object.headers) == 0 {
			if len(object.chunks) > 0 {
				v.undecodableHeaders++
			}
			continue
		}
		last := object.headers[len(object.headers)-1].header
		current[id] = last
		if len(object.headers) >= 2 {
			previous[id] = object.headers[len(object.headers)-2].header
		}
		v.objects[id] = objectData{header: last, chunks: object.chunks}
	}
	root, found := current[RootObjectID]
	if !found {
		return corruptf("the image has no root object header")
	}
	if !root.Kind.IsDirectory() || root.Name != "/" {
		return corruptf("object 1 is not a directory named `/`; this is not a YAFFS2 volume")
	}

	children := make(map[uint32][]uint32)
	for id, header := range current {
		if id == RootObjectID || id == UnlinkedObjectID || id == DeletedObjectID {
			continue
		}
		if header.Name == "" || header.Name == "/" || strings.Contains(header.Name, "/") {
			continue
		}
		children[header.Parent] = append(children[header.Parent], id)
	}

	pathOf := map[uint32]string{RootObjectID: "/"}
	v.addEntry(RootObjectID, root, true, 0, "/", false)
	type queued struct {
		id   uint32
		path string
	}
	queue := []queued{{id: RootObjectID, path: "/"}}
	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]
		kids := children[directory.id]
		sort.Slice(kids, func(left, right int) bool { return kids[left] < kids[right] })
		for _, child := range kids {
			if _, seen := pathOf[child]; seen {
				continue
			}
			header, found := current[child]
			if !found {
				continue
			}
			path := joinPath(directory.path, header.Name)
			pathOf[child] = path
			v.addEntry(child, header, directory.id == RootObjectID && child == RootObjectID, uint64(header.Parent), path, false)
			if header.Kind.IsDirectory() {
				queue = append(queue, queued{id: child, path: path})
			}
		}
	}

	var deletedIDs []uint32
	for id := range current {
		if id == RootObjectID || id == UnlinkedObjectID || id == DeletedObjectID {
			continue
		}
		if _, listed := pathOf[id]; !listed {
			deletedIDs = append(deletedIDs, id)
		}
	}
	sort.Slice(deletedIDs, func(left, right int) bool { return deletedIDs[left] < deletedIDs[right] })
	for _, id := range deletedIDs {
		header := current[id]
		shadow, found := previous[id]
		if !found || shadow.Name == "" || shadow.Name == "/" || strings.Contains(shadow.Name, "/") {
			v.unresolvedDeleted++
			continue
		}
		parentPath, found := pathOf[shadow.Parent]
		if !found {
			v.unresolvedDeleted++
			continue
		}
		path := joinPath(parentPath, shadow.Name)
		v.addEntry(id, header, false, uint64(shadow.Parent), path, true)
	}
	return nil
}

func (v *Volume) addEntry(id uint32, header Header, root bool, parent uint64, path string, deleted bool) {
	entry := Entry{
		Name:        header.Name,
		Path:        path,
		Inode:       uint64(id),
		ParentInode: parent,
		Kind:        header.Kind,
		IsDir:       header.Kind.IsDirectory(),
		IsFile:      header.Kind.IsFile(),
		IsSymlink:   header.Kind.IsSymlink(),
		IsHardLink:  header.Kind == KindHardLink,
		IsSpecial:   header.Kind == KindSpecial,
		Mode:        header.Mode,
		UID:         header.UID,
		GID:         header.GID,
		Size:        uint64(header.Size),
		Deleted:     deleted,
	}
	if root {
		entry.Name = "/"
		entry.Path = "/"
		entry.ParentInode = 0
	}
	var allocated uint64
	if header.Kind == KindHardLink {
		if target, found := v.objects[header.Equivalent]; found {
			entry.Size = uint64(target.header.Size)
			allocated = v.allocated(header.Equivalent, target.header)
			entry.Allocated = &allocated
		}
	} else if header.Kind.IsFile() {
		allocated = v.allocated(id, header)
		entry.Allocated = &allocated
	}
	if header.Kind == KindHardLink {
		// A hard link's bytes live in the object it names; when that object
		// is gone the link has a size but no stream.
		if _, found := v.objects[header.Equivalent]; !found {
			entry.Allocated = nil
		}
	}
	if deleted {
		entry.Allocated = nil
	}
	if atime, ok := nonzero(header.Atime); ok {
		entry.Atime, entry.HasAtime = atime, true
	}
	if mtime, ok := nonzero(header.Mtime); ok {
		entry.Mtime, entry.HasMtime = mtime, true
	}
	if ctime, ok := nonzero(header.Ctime); ok {
		entry.Ctime, entry.HasCtime = ctime, true
	}

	index := len(v.entries)
	v.entries = append(v.entries, entry)
	if _, found := v.byPath[path]; !found || !deleted {
		v.byPath[path] = index
	}
	if _, found := v.byRecord[entry.Inode]; !found {
		v.byRecord[entry.Inode] = index
	}
	if path != "/" {
		parentPath := cleanPath(path[:strings.LastIndexByte(path, '/')])
		if parentPath != path {
			v.children[parentPath] = append(v.children[parentPath], index)
		}
	}
}

func (v *Volume) allocated(id uint32, header Header) uint64 {
	object, found := v.objects[id]
	if !found || !header.Kind.IsFile() {
		return 0
	}
	target := id
	if header.Kind == KindHardLink {
		target = header.Equivalent
		object, found = v.objects[target]
		if !found {
			return 0
		}
	}
	page := uint64(v.layout.PageData)
	count := (uint64(object.header.Size) + page - 1) / page
	var stored uint64
	for chunk := uint32(1); chunk <= uint32(count); chunk++ {
		occurrence, found := object.chunks[chunk]
		if !found {
			return 0
		}
		available := uint64(occurrence.bytes)
		if available > page {
			available = page
		}
		stored += available
	}
	return stored
}

// Lookup returns the entry at an exact path.
func (v *Volume) Lookup(path string) (*Entry, error) {
	index, found := v.byPath[cleanPath(path)]
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	entry := v.entries[index]
	return &entry, nil
}

// EntryByInode returns the first entry for an object id.
func (v *Volume) EntryByInode(inode uint64) (*Entry, bool) {
	index, found := v.byRecord[inode]
	if !found {
		return nil, false
	}
	entry := v.entries[index]
	return &entry, true
}

// Stat returns the entry named by path.
func (v *Volume) Stat(path string) (*Entry, error) { return v.Lookup(path) }

// ListDir lists a directory's names, live and deleted, sorted by name.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	clean := cleanPath(path)
	entry, err := v.Lookup(clean)
	if err != nil {
		return nil, err
	}
	if !entry.IsDir {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, path)
	}
	indexes := v.children[clean]
	out := make([]Entry, 0, len(indexes))
	for _, index := range indexes {
		out = append(out, v.entries[index])
	}
	sort.SliceStable(out, func(left, right int) bool { return out[left].Name < out[right].Name })
	return out, nil
}

// SymlinkTarget returns the stored bytes of a symbolic link.  YAFFS2 keeps the
// target as the object's data chunks, so the target is read through the same
// chunk map a file uses.
func (v *Volume) SymlinkTarget(path string) (string, error) {
	entry, err := v.Lookup(path)
	if err != nil {
		return "", err
	}
	if !entry.IsSymlink {
		return "", fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	object, found := v.objects[uint32(entry.Inode)]
	if !found {
		return "", corruptf("symbolic link %s has no object header", path)
	}
	if object.header.Size > 64*1024 {
		return "", unsupportedf("symbolic link %s declares %d bytes, past the 64 KiB target cap",
			path, object.header.Size)
	}
	page := uint64(v.layout.PageData)
	count := (uint64(object.header.Size) + page - 1) / page
	target := make([]byte, 0, object.header.Size)
	scratch := make([]byte, v.layout.PageData)
	for chunk := uint32(1); chunk <= uint32(count); chunk++ {
		occurrence, found := object.chunks[chunk]
		if !found {
			break
		}
		available := int(occurrence.bytes)
		if available > v.layout.PageData {
			available = v.layout.PageData
		}
		if err := readAt(v.source, occurrence.page*uint64(v.layout.Stride), scratch[:available]); err != nil {
			return "", err
		}
		target = append(target, scratch[:available]...)
	}
	if uint64(len(target)) > uint64(object.header.Size) {
		target = target[:object.header.Size]
	}
	return string(target), nil
}

// ErrNotSymlink means a symbolic link was expected and the object is not one.
var ErrNotSymlink = fmt.Errorf("yaffs: not a symbolic link")
