package internal

// EWF format constants and fixed structure sizes.
var (
	// EVFSignature is the 8-byte EWF file header magic.
	EVFSignature = [8]byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00}
	// EWFFileHeaderLength is the length of the 13-byte EWF file header.
	EWFFileHeaderLength = int64(13)
	// SectionLength is the length of a 76-byte section descriptor.
	SectionLength = int64(76)
	// EWFSpecificationLength is the length of a 94-byte volume specification.
	EWFSpecificationLength = int64(94)
	// DiskSMARTLength is the length of a 1052-byte DiskSMART block.
	DiskSMARTLength = int64(1052)
	// TableSectionLength is the length of a 24-byte table header.
	TableSectionLength = int64(24)
	// chunkFooterLen is the Adler-32 footer of an uncompressed chunk.
	chunkFooterLen = int64(4)
)
