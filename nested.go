package forensic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal"
	"github.com/laenix/ewfgo/internal/data/aff4"
	"github.com/laenix/ewfgo/internal/data/containers/androidsparse"
	"github.com/laenix/ewfgo/internal/data/containers/certstore"
	"github.com/laenix/ewfgo/internal/data/containers/clfs"
	"github.com/laenix/ewfgo/internal/data/containers/dmg"
	"github.com/laenix/ewfgo/internal/data/containers/ewf"
	"github.com/laenix/ewfgo/internal/data/containers/l01"
	"github.com/laenix/ewfgo/internal/data/containers/msdelta"
	"github.com/laenix/ewfgo/internal/data/containers/ole"
	"github.com/laenix/ewfgo/internal/data/containers/ooxml"
	"github.com/laenix/ewfgo/internal/data/containers/pdf"
	"github.com/laenix/ewfgo/internal/data/containers/pst"
	"github.com/laenix/ewfgo/internal/data/containers/qcow2"
	"github.com/laenix/ewfgo/internal/data/containers/realm"
	"github.com/laenix/ewfgo/internal/data/containers/rotated"
	"github.com/laenix/ewfgo/internal/data/containers/vdi"
	"github.com/laenix/ewfgo/internal/data/containers/vhd"
	"github.com/laenix/ewfgo/internal/data/containers/vhdx"
	"github.com/laenix/ewfgo/internal/data/containers/vmdk"
	"github.com/laenix/ewfgo/internal/data/containers/vmdkdisk"
	"github.com/laenix/ewfgo/internal/data/containers/wim"
	"github.com/laenix/ewfgo/internal/data/memory/dmp"
	"github.com/laenix/ewfgo/internal/data/memory/hiber"
	"github.com/laenix/ewfgo/internal/data/memory/lime"
	"github.com/laenix/ewfgo/internal/data/partition/super"
	"github.com/laenix/ewfgo/internal/data/source"
)

// NestedOptions bounds a recursive container walk.
type NestedOptions struct {
	Options Options

	// MaxDepth limits container nesting. 0 uses 12.
	MaxDepth int
	// MaxNodes limits the total node count. 0 uses 20,000.
	MaxNodes int
	// MaxEntries limits entries read from one directory. 0 uses 10,000.
	MaxEntries uint64
	// InspectFiles descends into files to find containers inside filesystems
	// and archives. When false only container, partition and filesystem nodes
	// are produced.
	InspectFiles bool
	// Resolver opens side files referenced by split VMDK descriptors.
	Resolver func(name string) (ByteSource, error)
}

// DefaultNestedOptions returns bounded defaults.
func DefaultNestedOptions() NestedOptions {
	return NestedOptions{
		MaxDepth:     12,
		MaxNodes:     20_000,
		MaxEntries:   10_000,
		InspectFiles: true,
	}
}

// NestedNode is one node of a nested evidence tree.
type NestedNode struct {
	Name string
	// Path is a display breadcrumb, for example
	// "evidence.zip/disk.E01/partition-0/FAT32/etc/hosts".
	Path string
	// Kind is the detected artifact kind ("ZIP", "E01", "partition", "FAT32",
	// "file", "memory dump", ...).
	Kind   string
	Detail string
	Size   uint64
	// Source is the byte range backing this node, when it is byte-addressable.
	Source ByteSource
	// Err is a non-fatal failure encountered while inspecting this node.
	Err      string
	Children []*NestedNode
}

// NestedTree is a recursively inspected evidence tree. Close releases the
// top-level handles the tree was built from.
type NestedTree struct {
	Root      *NestedNode
	Nodes     int
	Truncated bool

	closeOnce sync.Once
	closers   []io.Closer
	closeErr  error
}

// OpenNested opens an evidence file and recursively inspects every container,
// partition, filesystem, archive and file it can identify, up to the configured
// limits. A failed nested artifact is recorded in NestedNode.Err; it does not
// abort sibling inspection.
func OpenNested(ctx context.Context, imagePath string, opts NestedOptions) (*NestedTree, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if imagePath == "" {
		return nil, fmt.Errorf("%w: empty image path", ErrInvalidArgument)
	}
	opts = normalizeNestedOptions(opts)

	if pathIsDiskImage(imagePath) {
		img, err := Open(ctx, imagePath, opts.Options)
		if err != nil {
			return nil, err
		}
		tree := &NestedTree{closers: []io.Closer{img}}
		builder := newNestedBuilder(ctx, opts, tree)
		name := filepath.Base(imagePath)
		root := builder.node(nil, name, name, img.Format(), imageDetail(img), img.Size(), img.Source())
		tree.Root = root
		builder.addPartitions(root, img, 1)
		return tree, nil
	}

	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.Options.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", imagePath, err)
	}
	tree := &NestedTree{closers: []io.Closer{raw}}
	builder := newNestedBuilder(ctx, opts, tree)
	name := filepath.Base(imagePath)
	root := builder.node(nil, name, name, "data", "", raw.Len(), raw)
	tree.Root = root
	builder.fill(root, raw, 0)
	return tree, nil
}

// OpenNestedSource recursively inspects an already-opened source. The caller
// keeps ownership of src; NestedTree.Close does not close it.
func OpenNestedSource(ctx context.Context, src ByteSource, opts NestedOptions) (*NestedTree, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil nested source", ErrInvalidArgument)
	}
	opts = normalizeNestedOptions(opts)
	tree := &NestedTree{}
	builder := newNestedBuilder(ctx, opts, tree)
	root := builder.node(nil, "source", "source", "data", "", src.Len(), src)
	tree.Root = root
	builder.fill(root, src, 0)
	return tree, nil
}

// Close releases top-level handles. It is idempotent.
func (t *NestedTree) Close() error {
	if t == nil {
		return nil
	}
	t.closeOnce.Do(func() {
		for _, closer := range t.closers {
			if err := closer.Close(); err != nil && t.closeErr == nil {
				t.closeErr = err
			}
		}
		t.closers = nil
	})
	return t.closeErr
}

func normalizeNestedOptions(opts NestedOptions) NestedOptions {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 12
	}
	if opts.MaxNodes <= 0 {
		opts.MaxNodes = 20_000
	}
	if opts.MaxEntries == 0 {
		opts.MaxEntries = 10_000
	}
	if opts.Options.Limits.MaxEntries == 0 {
		opts.Options.Limits.MaxEntries = opts.MaxEntries
	}
	return opts
}

func imageDetail(img *Image) string {
	return fmt.Sprintf("%d bytes, %d-byte sectors", img.Size(), img.SectorSize())
}

type nestedBuilder struct {
	ctx  context.Context
	opts NestedOptions
	tree *NestedTree
	next uint64
}

func newNestedBuilder(ctx context.Context, opts NestedOptions, tree *NestedTree) *nestedBuilder {
	return &nestedBuilder{ctx: ctx, opts: opts, tree: tree}
}

func (b *nestedBuilder) allocID() source.ID {
	b.next++
	return source.ID(b.next)
}

func (b *nestedBuilder) node(parent *NestedNode, name, nodePath, kind, detail string, size uint64, src ByteSource) *NestedNode {
	if b.tree.Nodes >= b.opts.MaxNodes {
		b.tree.Truncated = true
		return nil
	}
	child := &NestedNode{
		Name: name, Path: nodePath, Kind: kind, Detail: detail,
		Size: size, Source: src,
	}
	b.tree.Nodes++
	if parent != nil {
		parent.Children = append(parent.Children, child)
	}
	return child
}

func (b *nestedBuilder) addChild(parent *NestedNode, name, nodePath, kind, detail string, size uint64, src ByteSource) *NestedNode {
	if parent == nil {
		return nil
	}
	return b.node(parent, name, nodePath, kind, detail, size, src)
}

func (b *nestedBuilder) depthExceeded(depth int) bool {
	if depth > b.opts.MaxDepth {
		b.tree.Truncated = true
		return true
	}
	return false
}

func joinNodePath(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

// ---- detection and dispatch ------------------------------------------------

func (b *nestedBuilder) fill(node *NestedNode, src ByteSource, depth int) {
	if node == nil || src == nil || b.depthExceeded(depth) {
		return
	}
	head, err := readHead(src, 512)
	if err != nil {
		node.Err = err.Error()
		return
	}

	switch {
	case len(head) >= 8 && bytes.Equal(head[:8], internal.EVFSignature[:]):
		b.fillEWF(node, src, depth)
	case l01.MatchesSignature(head):
		b.fillL01(node, src, depth)
	case wim.Detect(head):
		b.fillWIM(node, src, depth)
	case looksLikeAFF4("", head):
		b.fillAFF4(node, src, depth)
	case looksLikeOOXML("", head):
		b.fillOOXML(node, src)
	case len(head) >= 8 && bytes.Equal(head[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
		b.fillOLE(node, src, depth)
	case clfs.Detect(head) || clfs.DetectContainer(head):
		container, err := clfs.Open(src)
		if err != nil {
			node.Kind = "CLFS"
			node.Err = err.Error()
			return
		}
		node.Kind = "CLFS"
		node.Detail = container.Kind().Label()
	case certstore.Detect(head):
		b.fillCertificateStore(node, src)
	case realm.LooksLike(head):
		db, err := realm.OpenWithLimits(b.allocID(), src, realm.DefaultLimits())
		if err != nil {
			node.Kind = "Realm"
			node.Err = err.Error()
			return
		}
		node.Kind = "Realm"
		node.Detail = fmt.Sprintf("format %d, %d tables, %d rows",
			db.Header.FormatVersion, len(db.Tables), db.RowCount())
	case deltaKind(head):
		node.Kind = "MSDelta"
		node.Detail = "Windows delta patch"
	case rotated.MatchesSignature(head):
		if compression, ok := rotated.Detect(head); ok {
			b.fillCompressed(node, src, depth, compression.Label())
		}
	case pdf.MatchesSignature(head):
		b.fillPDF(node, src, depth)
		return
	case pst.MatchesSignature(head):
		b.fillPST(node, src)
		return
	case b.fillMemory(node, src, head):
		return
	case b.fillSuper(node, src, depth):
		return
	case b.looksLikeArchive(head):
		b.fillArchive(node, src, depth)
	default:
		if container := decodeContainerSource(src, b.opts); container != nil {
			if container.err != nil {
				node.Kind = container.format
				node.Err = container.err.Error()
				return
			}
			b.fillDisk(node, container.source, container.format, "", depth)
			return
		}
		b.fillRawDisk(node, src, depth)
	}
}

func deltaKind(head []byte) bool {
	_, ok := msdelta.Identify(head)
	return ok
}

func (b *nestedBuilder) looksLikeArchive(head []byte) bool {
	switch {
	case bytes.HasPrefix(head, []byte{'P', 'K', 3, 4}),
		bytes.HasPrefix(head, []byte{'P', 'K', 5, 6}),
		bytes.HasPrefix(head, []byte{'P', 'K', 7, 8}),
		bytes.HasPrefix(head, []byte("!<arch>\n")),
		bytes.HasPrefix(head, []byte("MSCF")),
		bytes.HasPrefix(head, []byte("xar!")),
		bytes.HasPrefix(head, []byte("070701")),
		bytes.HasPrefix(head, []byte("070702")),
		bytes.HasPrefix(head, []byte("070707")),
		bytes.HasPrefix(head, []byte{0xc7, 0x71}),
		bytes.HasPrefix(head, []byte{0x71, 0xc7}),
		bytes.HasPrefix(head, []byte("ANDROID BACKUP\n")),
		bytes.HasPrefix(head, []byte("MIUI BACKUP\n")),
		bytes.HasPrefix(head, []byte("Rar!\x1a\x07")),
		bytes.HasPrefix(head, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}):
		return true
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return true
	}
	return false
}

// ---- disk images ------------------------------------------------------------

// containerSource is the result of sniffing a disk-container byte source.
type containerSource struct {
	source ByteSource
	format string
	err    error
}

// decodeContainerSource recognises a virtual-disk container over a source.
// A nil result means the source does not look like one of these containers.
func decodeContainerSource(src ByteSource, opts NestedOptions) *containerSource {
	head, err := readHead(src, 512)
	if err != nil {
		return nil
	}
	footer := func() []byte {
		if src.Len() < 512 {
			return nil
		}
		data, err := source.ReadVecAt(src, src.Len()-512, 512)
		if err != nil {
			return nil
		}
		return data
	}

	switch {
	case vhdx.MatchesSignature(head):
		out, err := vhdx.Open(1, src)
		return &containerSource{source: out, format: "VHDX", err: err}
	case qcow2.MatchesSignature(head):
		out, err := qcow2.Open(1, src)
		return &containerSource{source: out, format: "QCOW2", err: err}
	case vdi.MatchesSignature(head):
		out, err := vdi.Open(1, src)
		return &containerSource{source: out, format: "VDI", err: err}
	case vmdk.MatchesSignature(head):
		out, err := vmdk.Open(1, src)
		return &containerSource{source: out, format: "VMDK", err: err}
	case androidsparse.MatchesSignature(head):
		out, err := androidsparse.Open(1, src)
		return &containerSource{source: out, format: "Android sparse", err: err}
	case vmdkdisk.MatchesDescriptor(head):
		descriptorBytes, err := readHead(src, 256<<10)
		var descriptor *vmdkdisk.Descriptor
		if err == nil {
			descriptor, err = vmdkdisk.ParseDescriptor(descriptorBytes)
		}
		if err != nil {
			return &containerSource{format: "VMDK descriptor", err: err}
		}
		var resolver vmdkdisk.Resolver
		if opts.Resolver != nil {
			resolver = func(name string) (ByteSource, error) { return opts.Resolver(name) }
		}
		if resolver == nil {
			return &containerSource{format: "VMDK descriptor",
				err: fmt.Errorf("%w: a nested split VMDK needs NestedOptions.Resolver", ErrUnsupported)}
		}
		out, err := vmdkdisk.Assemble(1, descriptor, resolver)
		return &containerSource{source: out, format: "VMDK descriptor", err: err}
	}
	if footerBytes := footer(); footerBytes != nil {
		switch {
		case dmg.Detect(footerBytes):
			out, err := dmg.Open(src)
			return &containerSource{source: out, format: "DMG", err: err}
		case vhd.MatchesFooter(footerBytes):
			out, err := vhd.Open(1, src)
			return &containerSource{source: out, format: "VHD", err: err}
		}
	}
	return nil
}

// fillDisk opens a decoded disk source and adds partition/filesystem children.
func (b *nestedBuilder) fillDisk(node *NestedNode, src ByteSource, kind, detail string, depth int) {
	node.Kind = kind
	if detail != "" {
		node.Detail = detail
	}
	node.Source = src
	node.Size = src.Len()
	if b.depthExceeded(depth + 1) {
		return
	}
	img, err := OpenSource(b.ctx, src, b.opts.Options)
	if err != nil {
		node.Err = err.Error()
		return
	}
	parts, err := img.Partitions(b.ctx)
	if err != nil {
		node.Err = err.Error()
		return
	}
	if node.Detail == "" {
		node.Detail = fmt.Sprintf("%d bytes, %d partition(s)", src.Len(), len(parts))
	}
	if len(parts) == 0 {
		// The decoded medium may itself be a virtual-disk file: an E01 can
		// contain a VHDX/QCOW2/VDI/VMDK image instead of a raw disk. Open the
		// container and walk its guest partitions before treating the bytes as
		// an embedded archive or document.
		if b.fillEmbeddedContainer(node, src, depth) {
			return
		}
		// A disk-like container may itself hold a single embedded file (a TAR
		// payload, a document, a memory dump) with no partition table.
		head, headErr := readHead(src, 512)
		if headErr == nil && b.looksLikeEmbedded(head) {
			content := b.addChild(node, "content", joinNodePath(node.Path, "content"), "data",
				fmt.Sprintf("%d bytes", src.Len()), src.Len(), src)
			if content != nil {
				b.fill(content, src, depth+1)
			}
		}
		return
	}
	b.addPartitions(node, img, depth+1)
}

// fillEmbeddedContainer opens a virtual-disk container (VHDX/QCOW2/VDI/VMDK/
// DMG/VHD) that sits inside the current source. It reports whether a container
// was recognised.
func (b *nestedBuilder) fillEmbeddedContainer(node *NestedNode, src ByteSource, depth int) bool {
	container := decodeContainerSource(src, b.opts)
	if container == nil {
		return false
	}
	size := src.Len()
	if container.source != nil {
		size = container.source.Len()
	}
	child := b.addChild(node, "content", joinNodePath(node.Path, "content"),
		container.format, "", size, container.source)
	if child == nil {
		return true
	}
	if container.err != nil {
		child.Err = container.err.Error()
		return true
	}
	b.fillDisk(child, container.source, container.format,
		fmt.Sprintf("%d bytes", container.source.Len()), depth+1)
	return true
}

// looksLikeEmbedded reports a container signature that can live directly in a
// disk-like payload without a partition table.
func (b *nestedBuilder) looksLikeEmbedded(head []byte) bool {
	switch {
	case b.looksLikeArchive(head), looksLikeAFF4("", head), looksLikeOOXML("", head),
		rotated.MatchesSignature(head), pdf.MatchesSignature(head),
		pst.MatchesSignature(head), deltaKind(head):
		return true
	case l01.MatchesSignature(head), wim.Detect(head):
		return true
	case len(head) >= 8 && bytes.Equal(head[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
		return true
	}
	return b.fillMemoryNode(head)
}

// fillMemoryNode reports only whether head looks like a memory dump; it is
// used for signature classification without parsing.
func (b *nestedBuilder) fillMemoryNode(head []byte) bool {
	return (len(head) >= 4 && lime.LooksLike(head[:4])) ||
		(len(head) >= 4 && (string(head[:4]) == "hibr" || string(head[:4]) == "HIBR")) ||
		dmp.LooksLike(head)
}

// fillRawDisk tries to interpret an unknown source as a disk image. It reports
// whether any partition or whole-volume filesystem was found.
func (b *nestedBuilder) fillRawDisk(node *NestedNode, src ByteSource, depth int) bool {
	if b.depthExceeded(depth + 1) {
		return true
	}
	img, err := OpenSource(b.ctx, src, b.opts.Options)
	if err != nil {
		return false
	}
	parts, err := img.Partitions(b.ctx)
	if err != nil || len(parts) == 0 {
		return false
	}
	node.Kind = "raw disk"
	node.Detail = fmt.Sprintf("%d bytes, %d partition(s)", src.Len(), len(parts))
	node.Source = src
	b.addPartitions(node, img, depth+1)
	return true
}

func (b *nestedBuilder) addPartitions(node *NestedNode, img *Image, depth int) {
	if node == nil {
		return
	}
	parts, err := img.Partitions(b.ctx)
	if err != nil {
		node.Err = err.Error()
		return
	}
	if len(parts) == 0 && node.Source != nil {
		b.fillEmbeddedContainer(node, node.Source, depth)
		return
	}
	for _, part := range parts {
		kind := "partition"
		if part.WholeVolume() {
			kind = "volume"
		}
		detail := fmt.Sprintf("%s, %s, %d bytes", part.TypeName(), part.Format(), part.Length())
		child := b.addChild(node, fmt.Sprintf("partition-%d", part.Index()), joinNodePath(node.Path, fmt.Sprintf("partition-%d", part.Index())), kind, detail, part.Length(), part.Source())
		if child == nil || b.depthExceeded(depth) {
			continue
		}
		if part.Encrypted() {
			child.Kind = "encrypted volume"
			continue
		}
		fsys, fsErr := part.OpenFilesystem(b.ctx)
		if fsErr != nil {
			if part.Format() == "unknown" {
				content := b.addChild(child, "content", joinNodePath(child.Path, "content"), "data",
					fmt.Sprintf("%d bytes", part.Length()), part.Length(), part.Source())
				if content != nil {
					b.fill(content, part.Source(), depth+1)
				}
			} else {
				child.Err = fsErr.Error()
			}
			continue
		}
		info := fsys.Info()
		fsNode := b.addChild(child, fsys.Type(), joinNodePath(child.Path, fsys.Type()), fsys.Type(),
			fmt.Sprintf("%s, block %d, sector %d", info.Label, info.BlockSize, info.SectorSize),
			part.Length(), nil)
		if fsNode != nil {
			b.walkFS(fsNode, fsys, "/", depth+1)
		}
		fsys.Close()
	}
}

// ---- filesystem walk --------------------------------------------------------

func (b *nestedBuilder) walkFS(node *NestedNode, fsys FileSystem, dir string, depth int) {
	if node == nil || b.depthExceeded(depth+1) {
		return
	}
	entries, err := fsys.ListDir(b.ctx, dir)
	if err != nil {
		node.Err = err.Error()
		return
	}
	if uint64(len(entries)) > b.opts.MaxEntries {
		entries = entries[:b.opts.MaxEntries]
		b.tree.Truncated = true
	}
	for _, entry := range entries {
		if entry.Name == "." || entry.Name == ".." {
			continue
		}
		kind := "file"
		switch {
		case entry.IsDir:
			kind = "directory"
		case entry.IsSymlink:
			kind = "symlink"
		}
		child := b.addChild(node, entry.Name, joinNodePath(node.Path, entry.Name), kind,
			fmt.Sprintf("%d bytes", entry.Size), entry.Size, nil)
		if child == nil {
			continue
		}
		if entry.IsDir {
			b.walkFS(child, fsys, entry.Path, depth+1)
			continue
		}
		if !entry.IsDir && !entry.IsSymlink && b.opts.InspectFiles && depth+1 <= b.opts.MaxDepth {
			file, err := fsys.Open(b.ctx, entry.Path)
			if err != nil {
				child.Err = err.Error()
				continue
			}
			src, err := file.OpenSource()
			file.Close()
			if err != nil {
				child.Err = err.Error()
				continue
			}
			child.Source = src
			b.fill(child, src, depth+1)
		}
	}
}

// ---- embedded containers ----------------------------------------------------

func (b *nestedBuilder) fillEWF(node *NestedNode, src ByteSource, depth int) {
	node.Kind = "E01"
	ewfSrc, _, err := ewf.OpenSources(b.allocID(), 1, []source.ByteSource{src})
	if err != nil {
		node.Err = err.Error()
		return
	}
	b.fillDisk(node, ewfSrc, "E01", "embedded EWF image", depth)
}

func (b *nestedBuilder) fillL01(node *NestedNode, src ByteSource, depth int) {
	image, err := l01.Open(src)
	if err != nil {
		node.Kind = "L01"
		node.Err = err.Error()
		return
	}
	node.Kind = "L01"
	entries, err := image.Entries()
	if err != nil {
		node.Err = err.Error()
		return
	}
	node.Detail = fmt.Sprintf("%d catalog entries", len(entries))
	if b.depthExceeded(depth + 1) {
		return
	}
	for _, entry := range entries {
		kind := "file"
		if entry.Kind == l01.KindDirectory {
			kind = "directory"
		}
		detail := ""
		if entry.Size != nil {
			detail = fmt.Sprintf("%d bytes", *entry.Size)
		}
		child := b.addChild(node, entry.Name, joinNodePath(node.Path, entry.Path), kind, detail, sizeOrZero(entry.Size), nil)
		if child == nil || kind == "directory" || !b.opts.InspectFiles {
			continue
		}
		stream, err := image.OpenFile(entry.Path, b.allocID())
		if err != nil {
			child.Err = err.Error()
			continue
		}
		child.Source = stream
		b.fill(child, stream, depth+1)
	}
}

func sizeOrZero(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func (b *nestedBuilder) fillWIM(node *NestedNode, src ByteSource, depth int) {
	container, err := wim.Open(src)
	if err != nil {
		node.Kind = "WIM"
		node.Err = err.Error()
		return
	}
	info := container.Info()
	node.Kind = "WIM"
	node.Detail = fmt.Sprintf("%d images, %s compression", len(container.Images()), info.Compression.String())
	if b.depthExceeded(depth + 1) {
		return
	}
	images := container.Images()
	for imageIndex := range images {
		image := &images[imageIndex]
		imageNode := b.addChild(node, "image", joinNodePath(node.Path, fmt.Sprintf("image-%d", image.Index)),
			"WIM image", fmt.Sprintf("index %d", image.Index), 0, nil)
		if imageNode == nil {
			continue
		}
		if image.Name != nil && *image.Name != "" {
			imageNode.Name = *image.Name
		}
		for entryIndex := range image.Entries {
			entry := &image.Entries[entryIndex]
			kind := "file"
			if entry.IsDirectory() {
				kind = "directory"
			}
			child := b.addChild(imageNode, entry.Name, joinNodePath(imageNode.Path, entry.Path), kind,
				fmt.Sprintf("%d bytes", entry.Size), entry.Size, nil)
			if child == nil || kind == "directory" || !b.opts.InspectFiles {
				continue
			}
			stream, err := container.OpenEntry(image.Index, entry.Path)
			if err != nil {
				child.Err = err.Error()
				continue
			}
			child.Source = stream
			b.fill(child, stream, depth+1)
		}
	}
}

func (b *nestedBuilder) fillAFF4(node *NestedNode, src ByteSource, depth int) {
	container, err := aff4.Open(src, aff4.DefaultLimits())
	if err != nil {
		node.Kind = "AFF4"
		node.Err = err.Error()
		return
	}
	facts := container.Facts()
	node.Kind = "AFF4"
	node.Detail = fmt.Sprintf("version %s, %d streams, %d hashes", container.Version(), len(facts.Streams), len(facts.Hashes))
	if b.depthExceeded(depth + 1) {
		return
	}
	for _, stream := range container.Streams() {
		child := b.addChild(node, stream.URI, joinNodePath(node.Path, stream.URI), "AFF4 stream",
			stream.ClassLabel(), sizeOrZero(stream.Size), nil)
		if child == nil || !b.opts.InspectFiles {
			continue
		}
		streamSource, err := container.OpenStream(stream.URI)
		if err != nil {
			child.Err = err.Error()
			continue
		}
		child.Source = streamSource
		child.Size = streamSource.Len()
		b.fill(child, streamSource, depth+1)
	}
}

func (b *nestedBuilder) fillOOXML(node *NestedNode, src ByteSource) {
	doc, err := ooxml.Open(src, ooxml.DefaultLimits())
	if err != nil {
		node.Kind = "OOXML"
		node.Err = err.Error()
		return
	}
	node.Kind = "OOXML"
	title := ""
	if doc.Core.Title != nil {
		title = *doc.Core.Title
	}
	node.Detail = fmt.Sprintf("%s, %d sheets, %d slides", doc.Kind.Label(), len(doc.Sheets), slideCount(doc))
	if title != "" {
		node.Detail += ", title " + title
	}
}

func slideCount(doc *ooxml.Document) int {
	if doc.SlideCount == nil {
		return 0
	}
	return *doc.SlideCount
}

func (b *nestedBuilder) fillOLE(node *NestedNode, src ByteSource, depth int) {
	file, err := ole.Open(src)
	if err != nil {
		node.Kind = "OLE/CFB"
		node.Err = err.Error()
		return
	}
	node.Kind = "OLE/CFB"
	node.Detail = fmt.Sprintf("CFB v%d", file.Header().MajorVersion)
	if b.depthExceeded(depth + 1) {
		return
	}
	var walk func(parent *NestedNode, storage string, level int)
	walk = func(parent *NestedNode, storage string, level int) {
		if b.depthExceeded(level) {
			return
		}
		entries, err := file.ListStorage(storage)
		if err != nil {
			parent.Err = err.Error()
			return
		}
		for index := range entries {
			entry := &entries[index]
			childPath := path.Join(storage, entry.Name)
			kind := "stream"
			if entry.IsStorage() {
				kind = "storage"
			}
			child := b.addChild(parent, entry.Name, joinNodePath(parent.Path, entry.Name), kind,
				fmt.Sprintf("%d bytes", entry.Size), entry.Size, nil)
			if child == nil {
				continue
			}
			if entry.IsStorage() {
				walk(child, childPath, level+1)
				continue
			}
			if !b.opts.InspectFiles {
				continue
			}
			stream, err := file.OpenStream(childPath, b.allocID())
			if err != nil {
				child.Err = err.Error()
				continue
			}
			child.Source = stream
			b.fill(child, stream, level+1)
		}
	}
	walk(node, "/", depth+1)
}

func (b *nestedBuilder) fillCertificateStore(node *NestedNode, src ByteSource) {
	store, err := certstore.Open(src, certstore.DefaultLimits())
	if err != nil {
		node.Kind = "certificate store"
		node.Err = err.Error()
		return
	}
	node.Kind = "certificate store"
	node.Detail = fmt.Sprintf("%d certificates, %d names", len(store.Certificates), len(store.Names))
	for index := range store.Certificates {
		certificate := &store.Certificates[index]
		child := b.addChild(node, fmt.Sprintf("certificate-%d", index),
			joinNodePath(node.Path, fmt.Sprintf("certificate-%d", index)), "certificate",
			fmt.Sprintf("%d bytes, SHA-256 %s", certificate.Len, certificate.SHA256), certificate.Len, nil)
		if child == nil || !b.opts.InspectFiles {
			continue
		}
		blob, err := store.CertificateSource(index, b.allocID())
		if err != nil {
			child.Err = err.Error()
			continue
		}
		child.Source = blob
		b.fill(child, blob, 1)
	}
}

func (b *nestedBuilder) fillCompressed(node *NestedNode, src ByteSource, depth int, format string) {
	decoded, err := rotated.Decode(b.allocID(), src, rotated.DefaultLimits())
	if err != nil {
		node.Kind = format
		node.Err = err.Error()
		return
	}
	node.Kind = format
	node.Detail = fmt.Sprintf("decodes to %d bytes", decoded.Len())
	child := b.addChild(node, "decoded", joinNodePath(node.Path, "decoded"), "data", "", decoded.Len(), decoded)
	if child != nil {
		b.fill(child, decoded, depth+1)
	}
}

// fillPDF reports a PDF document and walks its embedded files as nested
// members.
func (b *nestedBuilder) fillPDF(node *NestedNode, src ByteSource, depth int) {
	doc, err := pdf.Open(src, pdf.DefaultLimits())
	if err != nil {
		node.Kind = "PDF"
		node.Err = err.Error()
		return
	}
	node.Kind = "PDF"
	node.Detail = fmt.Sprintf("PDF %s, %d page(s), %d embedded file(s)",
		doc.Version, doc.Pages().Counted, len(doc.EmbeddedFiles))
	for index, file := range doc.EmbeddedFiles {
		// Attachment names are display labels, not archive paths: replace both
		// separator characters without embedding a Windows path literal.
		const backslash = rune(92)
		name := strings.Map(func(r rune) rune {
			if r == '/' || r == backslash {
				return '_'
			}
			return r
		}, file.Name)
		if name == "" {
			name = fmt.Sprintf("attachment-%d", index+1)
		}
		attachment, openErr := doc.OpenAttachmentIndex(index, b.allocID())
		if openErr != nil {
			child := b.addChild(node, name, joinNodePath(node.Path, name), "PDF attachment", "", 0, nil)
			if child != nil {
				child.Err = openErr.Error()
			}
			continue
		}
		child := b.addChild(node, name, joinNodePath(node.Path, name), "PDF attachment",
			strings.Join(file.Filters, ","), attachment.Len(), attachment)
		if child != nil {
			b.fill(child, attachment, depth+1)
		}
	}
}

// fillPST reports an Outlook store without walking every message.
func (b *nestedBuilder) fillPST(node *NestedNode, src ByteSource) {
	reader, err := pst.Open(src, pst.DefaultLimits())
	if err != nil {
		node.Kind = "PST/OST"
		node.Err = err.Error()
		return
	}
	stats := reader.Stats()
	node.Kind = "PST/OST"
	node.Detail = fmt.Sprintf("%s %d, %s, %d folder node(s), %d message node(s)",
		reader.Header().ContentType.Label(), stats.Version, stats.Format.Label(),
		stats.FolderNodes, stats.MessageNodes)
}

func (b *nestedBuilder) fillMemory(node *NestedNode, src ByteSource, head []byte) bool {
	switch {
	case len(head) >= 4 && lime.LooksLike(head[:4]):
		report, err := lime.Read(src, lime.DefaultLimits())
		if err != nil {
			node.Kind = "memory dump"
			node.Err = err.Error()
			return true
		}
		node.Kind = "memory dump"
		node.Detail = fmt.Sprintf("LiME, %d ranges, %d stored bytes", report.RangeCount(), report.StoredBytes)
		return true
	case len(head) >= 4 && (string(head[:4]) == "hibr" || string(head[:4]) == "HIBR"):
		report, err := hiber.Read(src)
		if err != nil {
			node.Kind = "memory dump"
			node.Err = err.Error()
			return true
		}
		node.Kind = "memory dump"
		node.Detail = fmt.Sprintf("hiberfil, signature %q", string(report.Signature[:]))
		return true
	case dmp.LooksLike(head):
		report, err := dmp.ReadAnyDump(src, dmp.DefaultLimits(), dmp.DefaultMiniDumpLimits())
		if err != nil {
			node.Kind = "memory dump"
			node.Err = err.Error()
			return true
		}
		node.Kind = "memory dump"
		if report.Kernel != nil {
			node.Detail = "Windows kernel dump, " + report.Kernel.DumpTypeLabel()
		} else {
			node.Detail = "Windows minidump"
		}
		return true
	}
	return false
}

func (b *nestedBuilder) fillSuper(node *NestedNode, src ByteSource, depth int) bool {
	detection, err := super.Detect(src)
	if err != nil || !detection.Present || !detection.GeometryValid {
		return false
	}
	image, err := super.Open(src)
	if err != nil {
		node.Kind = "Android super image"
		node.Err = err.Error()
		return true
	}
	node.Kind = "Android super image"
	node.Detail = fmt.Sprintf("%d partitions, metadata slot %d", len(image.Partitions()), image.MetadataSlot())
	if b.depthExceeded(depth + 1) {
		return true
	}
	partitions := image.Partitions()
	for index := range partitions {
		partition := &partitions[index]
		child := b.addChild(node, partition.Name, joinNodePath(node.Path, partition.Name), "super partition",
			fmt.Sprintf("%d bytes", partition.Len), partition.Len, nil)
		if child == nil || !b.opts.InspectFiles {
			continue
		}
		partitionSource, err := image.OpenPartition(b.allocID(), index)
		if err != nil {
			child.Err = err.Error()
			continue
		}
		child.Source = partitionSource
		b.fill(child, partitionSource, depth+1)
	}
	return true
}

func (b *nestedBuilder) fillArchive(node *NestedNode, src ByteSource, depth int) {
	archive, err := OpenArchiveSource(b.ctx, src, b.opts.Options)
	if err != nil {
		node.Kind = "archive"
		node.Err = err.Error()
		return
	}
	defer archive.Close()
	entries, err := archive.Entries(b.ctx)
	if err != nil {
		node.Kind = archive.Format()
		node.Err = err.Error()
		return
	}
	node.Kind = archive.Format()
	node.Detail = fmt.Sprintf("%d entries", len(entries))
	if b.depthExceeded(depth + 1) {
		return
	}
	for _, entry := range entries {
		kind := entry.Kind
		if kind == "" {
			kind = "file"
		}
		child := b.addChild(node, path.Base(entry.Path), joinNodePath(node.Path, entry.Path), kind,
			fmt.Sprintf("%d bytes", entry.Size), entry.Size, nil)
		if child == nil || kind != "file" || !b.opts.InspectFiles {
			continue
		}
		stream, err := archive.OpenSource(b.ctx, entry.Path)
		if err != nil {
			child.Err = err.Error()
			continue
		}
		child.Source = stream
		b.fill(child, stream, depth+1)
	}
}

// ---- path sniffing ----------------------------------------------------------

// pathIsDiskImage reports whether Open handles this path as a disk image
// (including multi-segment EWF and split descriptors) rather than a single
// embedded source.
func pathIsDiskImage(imagePath string) bool {
	if isEWF(imagePath) {
		return true
	}
	f, err := os.Open(imagePath)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if vhdx.MatchesSignature(head) || qcow2.MatchesSignature(head) ||
		vdi.MatchesSignature(head) || vmdk.MatchesSignature(head) ||
		androidsparse.MatchesSignature(head) || vmdkdisk.MatchesDescriptor(head) ||
		vhd.MatchesHeader(head) {
		return true
	}
	if st, err := f.Stat(); err == nil && st.Size() >= 512 {
		footer := make([]byte, 512)
		if _, err := f.ReadAt(footer, st.Size()-512); err == nil {
			if dmg.Detect(footer) || vhd.MatchesFooter(footer) {
				return true
			}
		}
	}
	return false
}
