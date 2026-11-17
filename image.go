package forensic

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal"
	"github.com/laenix/ewfgo/internal/data/containers/androidsparse"
	"github.com/laenix/ewfgo/internal/data/containers/certstore"
	"github.com/laenix/ewfgo/internal/data/containers/clfs"
	"github.com/laenix/ewfgo/internal/data/containers/dmg"
	"github.com/laenix/ewfgo/internal/data/containers/ewf"
	"github.com/laenix/ewfgo/internal/data/containers/msdelta"
	"github.com/laenix/ewfgo/internal/data/containers/officelock"
	"github.com/laenix/ewfgo/internal/data/containers/qcow2"
	"github.com/laenix/ewfgo/internal/data/containers/realm"
	"github.com/laenix/ewfgo/internal/data/containers/vdi"
	"github.com/laenix/ewfgo/internal/data/containers/vhd"
	"github.com/laenix/ewfgo/internal/data/containers/vhdx"
	"github.com/laenix/ewfgo/internal/data/containers/vmdk"
	"github.com/laenix/ewfgo/internal/data/containers/vmdkdisk"
	"github.com/laenix/ewfgo/internal/data/inspect"
	"github.com/laenix/ewfgo/internal/data/partition/super"
	"github.com/laenix/ewfgo/internal/data/source"
)

// ImageInfo describes an opened evidence image.
type ImageInfo struct {
	Path string
	// Format is the outermost container: "E01", "raw", "VHD", "VHDX", "VMDK",
	// "VMDK descriptor", "QCOW2", "VDI", "DMG" or "Android sparse".
	Format string
	// Size is the guest-visible media size in bytes.
	Size       uint64
	SectorSize uint32

	CaseNumber      string
	EvidenceNumber  string
	Examiner        string
	Description     string
	Notes           string
	Platform        string
	AcquisitionDate string
	SystemDate      string
	MediaModel      string
	SerialNumber    string
	DeviceLabel     string

	// ChunkSectors/CompressionLevel are E01 acquisition geometry, zero for
	// other formats.
	ChunkSectors     uint32
	CompressionLevel uint8

	// StoredMD5/StoredSHA1 are the acquisition hashes recorded in the image;
	// nil when the container records none.
	StoredMD5  []byte
	StoredSHA1 []byte
}

// Image is an opened evidence image. It owns the underlying container file
// handles; call Close when done.
type Image struct {
	info   ImageInfo
	source ByteSource
	format string
	opts   Options
	sector uint32

	closeMu sync.Mutex
	closers []io.Closer
	closed  bool

	once      sync.Once
	report    *inspect.Report
	reportErr error

	volumeOnce sync.Once
	volumes    []*Volume
	volumeErr  error

	idMu   sync.Mutex
	nextID source.ID
}

// Open opens a path as an evidence image. It recognises EWF/E01 (including
// sibling E02/E03 segments), raw disks and the VHD, VHDX, VMDK, QCOW2, VDI,
// DMG and Android-sparse containers.
func Open(ctx context.Context, path string, opts Options) (*Image, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("%w: empty image path", ErrInvalidArgument)
	}

	if isLogicalImage(path) {
		return nil, fmt.Errorf("%w: %s is logical evidence (L01), not a disk image; use OpenLogical",
			ErrInvalidArgument, filepath.Base(path))
	}

	if isEWF(path) {
		src, info, err := ewf.OpenFile(1, 1, path)
		if err != nil {
			return nil, err
		}
		img := &Image{
			source:  src,
			format:  "E01",
			opts:    opts,
			sector:  src.SectorSize(),
			closers: []io.Closer{src},
		}
		img.info = ImageInfo{Path: path, Format: "E01", Size: src.Len(), SectorSize: src.SectorSize()}
		if info != nil {
			img.info.CaseNumber = info.CaseNumber
			img.info.EvidenceNumber = info.EvidenceNumber
			img.info.Examiner = info.Examiner
			img.info.Description = info.Description
			img.info.Notes = info.Notes
			img.info.Platform = info.Platform
			img.info.AcquisitionDate = info.AcquisitionDate
			img.info.SystemDate = info.SystemDate
			img.info.MediaModel = info.MediaModel
			img.info.SerialNumber = info.SerialNumber
			img.info.DeviceLabel = info.DeviceLabel
			img.info.ChunkSectors = info.ChunkSectors
			img.info.CompressionLevel = info.CompressionLevel
			img.info.StoredMD5 = info.StoredMD5
			img.info.StoredSHA1 = info.StoredSHA1
		}
		return img, nil
	}

	if name, opener, ok := nonDiskFormatFile(path); ok {
		return nil, fmt.Errorf("%w: %s is a %s container, not a disk image; use %s",
			ErrInvalidArgument, filepath.Base(path), name, opener)
	}

	if name := unimplementedStreamFormat(path); name != "" {
		return nil, fmt.Errorf("%w: %s is a %s stream/archive; its decoder is not implemented yet",
			ErrUnsupported, filepath.Base(path), name)
	}

	raw, err := source.OpenRawFileWithSectorSize(path, 0, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open image %s: %w", path, err)
	}
	img, err := openContainer(path, raw, opts)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return img, nil
}

// OpenSource wraps an already-opened byte source as an image. The source is
// treated as the decoded guest medium: no container sniffing is performed (use
// Open for that). The source is not closed by Image.Close; the caller keeps
// ownership.
func OpenSource(ctx context.Context, src ByteSource, opts Options) (*Image, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil source", ErrInvalidArgument)
	}
	sector := opts.sectorSize(src, 512)
	img := &Image{
		source: src,
		format: "source",
		opts:   opts,
		sector: sector,
		info: ImageInfo{
			Format:     "source",
			Size:       src.Len(),
			SectorSize: sector,
		},
	}
	return img, nil
}

// openContainer sniffs raw and recognises the virtual-disk containers. On
// success Image.closers owns raw.
func openContainer(path string, raw *source.ReaderAtSource, opts Options) (*Image, error) {
	headLen := uint64(512)
	if raw.Len() < headLen {
		headLen = raw.Len()
	}
	head, err := source.ReadVecAt(raw, 0, headLen)
	if err != nil {
		return nil, err
	}

	img := &Image{format: "raw", source: raw, opts: opts, sector: raw.SectorSize(), closers: []io.Closer{raw}}

	var (
		src    ByteSource
		format string
	)
	switch {
	case vhdx.MatchesSignature(head):
		src, err = vhdx.Open(1, raw)
		format = "VHDX"
	case qcow2.MatchesSignature(head):
		src, err = qcow2.Open(1, raw)
		format = "QCOW2"
	case vdi.MatchesSignature(head):
		src, err = vdi.Open(1, raw)
		format = "VDI"
	case vmdk.MatchesSignature(head):
		src, err = vmdk.Open(1, raw)
		format = "VMDK"
	case androidsparse.MatchesSignature(head):
		src, err = androidsparse.Open(1, raw)
		format = "Android sparse"
	case vmdkdisk.MatchesDescriptor(head):
		descBytes, descErr := readHead(raw, 256<<10)
		if descErr != nil {
			err = descErr
			format = "VMDK descriptor"
			break
		}
		format = "VMDK descriptor"
		var desc *vmdkdisk.Descriptor
		desc, err = vmdkdisk.ParseDescriptor(descBytes)
		if err == nil {
			src, err = vmdkdisk.Assemble(1, desc, opts.resolver(path, raw.ImageID()))
		}
	case matchesDMGFooter(raw):
		src, err = dmg.Open(raw)
		format = "DMG"
	case vhd.MatchesHeader(head) || matchesFooter(raw):
		src, err = vhd.Open(1, raw)
		format = "VHD"
	}
	if err != nil {
		return nil, fmt.Errorf("open %s container %s: %w", format, filepath.Base(path), err)
	}
	if src == nil {
		img.info = ImageInfo{
			Path: path, Format: "raw", Size: raw.Len(), SectorSize: raw.SectorSize(),
		}
		return img, nil
	}

	return &Image{
		source:  src,
		format:  format,
		opts:    opts,
		sector:  src.SectorSize(),
		closers: []io.Closer{raw},
		info: ImageInfo{
			Path: path, Format: format, Size: src.Len(), SectorSize: src.SectorSize(),
		},
	}, nil
}

func readHead(raw ByteSource, max uint64) ([]byte, error) {
	length := raw.Len()
	if length > max {
		length = max
	}
	return source.ReadVecAt(raw, 0, length)
}

func matchesDMGFooter(raw ByteSource) bool {
	if raw.Len() < 512 {
		return false
	}
	footer, err := source.ReadVecAt(raw, raw.Len()-512, 512)
	if err != nil {
		return false
	}
	return dmg.Detect(footer)
}

func matchesFooter(raw ByteSource) bool {
	if raw.Len() < 512 {
		return false
	}
	footer, err := source.ReadVecAt(raw, raw.Len()-512, 512)
	if err != nil {
		return false
	}
	return vhd.MatchesFooter(footer)
}

func (opts Options) resolver(imagePath string, imageID source.ImageID) vmdkdisk.Resolver {
	if opts.Resolver != nil {
		return func(name string) (ByteSource, error) { return opts.Resolver(name) }
	}
	dir := filepath.Dir(imagePath)
	return func(name string) (ByteSource, error) {
		if !filepath.IsAbs(name) {
			name = filepath.Join(dir, name)
		}
		return source.OpenRawFile(name, source.ID(1_000_000+len(name)), imageID)
	}
}

// unimplementedStreamFormat recognises formats the data layer has not ported
// yet, so Open reports an honest unsupported error instead of reading them as
// raw disks.
func unimplementedStreamFormat(imagePath string) string {
	f, err := os.Open(imagePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	head := make([]byte, 8)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "Zstandard"
	}
	return ""
}

func looksLikeOOXML(imagePath string, head []byte) bool {
	switch strings.ToLower(filepath.Ext(imagePath)) {
	case ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
		".pptx", ".pptm", ".potx", ".potm":
		return true
	}
	return bytes.HasPrefix(head, []byte{'P', 'K', 3, 4}) &&
		bytes.Contains(head, []byte("[Content_Types].xml"))
}

func looksLikeAFF4(imagePath string, head []byte) bool {
	if strings.EqualFold(filepath.Ext(imagePath), ".aff4") {
		return true
	}
	return bytes.HasPrefix(head, []byte{'P', 'K', 3, 4}) &&
		bytes.Contains(head, []byte("container.description"))
}

// nonDiskFormatFile recognises archive/document/stream containers that must
// not be opened as disk images, and names the public opener for each.
func nonDiskFormatFile(imagePath string) (name, opener string, ok bool) {
	f, err := os.Open(imagePath)
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]

	switch {
	case officelock.IsOwnerFileName(filepath.Base(imagePath)):
		return "Office owner file", "OpenOfficeOwner", true
	case certstore.Detect(head):
		return "certificate store", "OpenCertificateStore", true
	case realm.LooksLike(head) || strings.EqualFold(filepath.Ext(imagePath), ".realm"):
		return "Realm database", "OpenRealm", true
	case looksLikeAFF4(imagePath, head):
		return "AFF4", "OpenAFF4", true
	case looksLikeOOXML(imagePath, head):
		return "Office Open XML", "OpenDocument", true
	case clfs.Detect(head) || clfs.DetectContainer(head):
		return "CLFS", "OpenCLFS", true
	case super.MatchesSignature(head):
		return "Android super image", "OpenSuper", true
	case bytes.HasPrefix(head, []byte("PK\x03\x04")),
		bytes.HasPrefix(head, []byte("PK\x05\x06")),
		bytes.HasPrefix(head, []byte("PK\x07\x08")):
		return "ZIP", "OpenArchive", true
	case bytes.HasPrefix(head, []byte("!<arch>\n")):
		return "ar", "OpenArchive", true
	case bytes.HasPrefix(head, []byte("MSCF")):
		return "CAB", "OpenArchive", true
	case bytes.HasPrefix(head, []byte("Rar!\x1a\x07")):
		return "RAR", "OpenArchive", true
	case bytes.HasPrefix(head, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}):
		return "7-Zip", "OpenArchive", true
	case bytes.HasPrefix(head, []byte("ANDROID BACKUP\n")),
		bytes.HasPrefix(head, []byte("MIUI BACKUP\n")):
		return "Android backup", "OpenArchive", true
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return "gzip", "OpenCompressed", true
	case bytes.HasPrefix(head, []byte("BZh")):
		return "bzip2", "OpenCompressed", true
	case bytes.HasPrefix(head, []byte{0x04, 0x22, 0x4d, 0x18}),
		bytes.HasPrefix(head, []byte{0x02, 0x21, 0x4c, 0x18}):
		return "LZ4", "OpenCompressed", true
	case bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return "XZ", "OpenCompressed", true
	case bytes.HasPrefix(head, []byte{'M', 'S', 'W', 'I', 'M', 0, 0, 0}):
		return "WIM", "OpenWIM", true
	case bytes.HasPrefix(head, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
		return "OLE/CFB", "OpenOLE", true
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return "TAR", "OpenArchive", true
	}
	if kind, ok := msdelta.Identify(head); ok {
		return kind.Label() + " delta patch", "OpenDelta", true
	}
	return "", "", false
}

func isLogicalImage(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 8)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	for _, signature := range l01Signatures {
		if bytes.HasPrefix(head, signature) {
			return true
		}
	}
	return false
}

var l01Signatures = [][]byte{
	{'L', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00},
	{'L', 'E', 'F', '2', 0x0d, 0x0a, 0x81, 0x00},
}

func isEWF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var signature [8]byte
	if _, err := io.ReadFull(f, signature[:]); err != nil {
		return false
	}
	return bytes.Equal(signature[:], internal.EVFSignature[:])
}

// Info returns the image metadata captured at Open.
func (i *Image) Info() ImageInfo { return i.info }

// Format returns the outermost container format name.
func (i *Image) Format() string { return i.format }

// Path returns the path the image was opened from, empty for OpenSource.
func (i *Image) Path() string { return i.info.Path }

// Size returns the guest-visible media size in bytes.
func (i *Image) Size() uint64 { return i.source.Len() }

// SectorSize returns the sector size filesystem geometry uses. For containers
// this is the geometry the container declares; Options.SectorSize is only a
// hint for raw sources (and OpenSource inputs).
func (i *Image) SectorSize() uint32 {
	if i.sector != 0 {
		return i.sector
	}
	if i.source != nil && i.source.SectorSize() != 0 {
		return i.source.SectorSize()
	}
	return 512
}

// Source returns the image's byte source (the decoded guest media, never the
// container file bytes for EWF).
func (i *Image) Source() ByteSource { return i.source }

// Stats returns this image source's read counters.
func (i *Image) Stats() Stats { return i.source.Stats() }

// Graph returns the validated provenance graph: image node, partition nodes and
// detected filesystem nodes. It is built lazily and cached.
func (i *Image) Graph(ctx context.Context) (*source.SourceGraph, error) {
	report, err := i.analysis(ctx)
	if err != nil {
		return nil, err
	}
	return report.Graph, nil
}

func (i *Image) analysis(ctx context.Context) (*inspect.Report, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	i.once.Do(func() {
		i.report, i.reportErr = inspect.Image(i.source.SourceID(), i.source, i.SectorSize())
	})
	return i.report, i.reportErr
}

// Verify streams the whole guest medium through the strict read path and
// compares the computed MD5/SHA1 against the hashes recorded in the image.
// Match fields are false when the image records no such hash.
func (i *Image) Verify(ctx context.Context) (*HashVerification, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	md5Hash := md5.New()
	sha1Hash := sha1.New()
	const chunk = 4 << 20
	buf := make([]byte, chunk)
	var hashed uint64
	for offset := uint64(0); offset < i.source.Len(); {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		want := uint64(chunk)
		if want > i.source.Len()-offset {
			want = i.source.Len() - offset
		}
		n, err := i.source.ReadAt(offset, buf[:want])
		if err != nil {
			return nil, fmt.Errorf("verify at offset %d: %w", offset, err)
		}
		if uint64(n) != want {
			return nil, fmt.Errorf("verify at offset %d: %w", offset, io.ErrUnexpectedEOF)
		}
		md5Hash.Write(buf[:n])
		sha1Hash.Write(buf[:n])
		hashed += uint64(n)
		offset += uint64(n)
	}
	res := &HashVerification{
		StoredMD5:    i.info.StoredMD5,
		StoredSHA1:   i.info.StoredSHA1,
		ComputedMD5:  md5Hash.Sum(nil),
		ComputedSHA1: sha1Hash.Sum(nil),
		BytesHashed:  hashed,
	}
	res.MD5Match = len(res.StoredMD5) == md5.Size && bytes.Equal(res.StoredMD5, res.ComputedMD5)
	res.SHA1Match = len(res.StoredSHA1) == sha1.Size && bytes.Equal(res.StoredSHA1, res.ComputedSHA1)
	return res, nil
}

// HashVerification is the result of Image.Verify.
type HashVerification struct {
	StoredMD5    []byte
	StoredSHA1   []byte
	ComputedMD5  []byte
	ComputedSHA1 []byte
	MD5Match     bool
	SHA1Match    bool
	BytesHashed  uint64
}

// Close releases the image's container handles. It is idempotent.
func (i *Image) Close() error {
	i.closeMu.Lock()
	defer i.closeMu.Unlock()
	if i.closed {
		return nil
	}
	i.closed = true
	var firstErr error
	for _, closer := range i.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	i.closers = nil
	return firstErr
}

// DetectedFormat returns the volume format detected on the whole image (for an
// image with no partition table this is the filesystem; otherwise "unknown").
func (i *Image) DetectedFormat(ctx context.Context) (string, error) {
	report, err := i.analysis(ctx)
	if err != nil {
		return "", err
	}
	return report.VolumeFormat.Label(), nil
}
