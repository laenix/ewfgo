package forensic

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/laenix/ewfgo/internal/data/containers/pst"
	"github.com/laenix/ewfgo/internal/data/source"
)

// PSTFile is an opened Outlook PST/OST store.
type PSTFile struct {
	path   string
	reader *pst.Reader
	closer io.Closer
}

// PSTInfo summarizes a PST/OST store.
type PSTInfo struct {
	Path               string
	Kind               string
	Format             string
	Version            uint16
	PageBytes          int
	Encryption         string
	FileBytes          uint64
	Nodes              int
	Blocks             int
	FreeNodes          int
	FreeBlocks         int
	Folders            int
	Messages           int
	AssociatedMessages int
	ChecksumMismatches uint64
}

// PSTFolder describes one folder.
type PSTFolder struct {
	NID          uint64
	Parent       uint64
	Name         string
	ContentCount *uint32
	MessageCount int
	ChildFolders []uint64
	DataBID      uint64
	DataOffset   uint64
	SubnodeBID   uint64
	PageOffset   uint64
}

// PSTAttachment describes one attachment row.
type PSTAttachment struct {
	Index        int
	NID          uint32
	Filename     string
	Extension    string
	MIMEType     string
	Method       *uint32
	Size         uint64
	HasSize      bool
	ContentID    string
	Path         string
	SHA256       string
	Problem      string
	Embedded     bool
	ObjectBID    uint64
	ObjectOffset uint64
}

// PSTRecipient describes one recipient row.
type PSTRecipient struct {
	Index       int
	RowID       uint32
	DisplayName string
	AddressType string
	Email       string
	SMTP        string
	Kind        *uint32
	Problem     string
}

// PSTMessage describes one message.
type PSTMessage struct {
	NID              uint64
	Folder           uint64
	Associated       bool
	Subject          string
	SenderName       string
	SenderEmail      string
	MessageClass     string
	SubmitTime       time.Time
	HasSubmitTime    bool
	DeliveryTime     time.Time
	HasDeliveryTime  bool
	Size             *uint32
	Flags            *uint32
	Body             string
	HasBody          bool
	HTMLBytes        int
	RTFBytes         int
	TransportHeaders string
	MessageID        string
	DisplayTo        []string
	DisplayCc        []string
	DisplayBcc       []string
	HasAttachments   *bool
	Attachments      []PSTAttachment
	Recipients       []PSTRecipient
	DataBID          uint64
	DataOffset       uint64
	SubnodeBID       uint64
	PageOffset       uint64
}

// OpenPST opens an Outlook PST/OST store from a path.
func OpenPST(ctx context.Context, imagePath string, opts Options) (*PSTFile, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open PST %s: %w", imagePath, err)
	}
	file, err := OpenPSTSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, err
	}
	file.path = imagePath
	file.closer = raw
	return file, nil
}

// OpenPSTSource opens a PST/OST store over an existing byte source. The source
// is not closed by PSTFile.Close.
func OpenPSTSource(ctx context.Context, src ByteSource, opts Options) (*PSTFile, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil PST source", ErrInvalidArgument)
	}
	reader, err := pst.Open(src, pst.DefaultLimits())
	if err != nil {
		return nil, err
	}
	return &PSTFile{reader: reader}, nil
}

// Path returns the store path, empty for source opens.
func (p *PSTFile) Path() string { return p.path }

// Info returns the store summary.
func (p *PSTFile) Info() PSTInfo {
	stats := p.reader.Stats()
	header := p.reader.Header()
	return PSTInfo{
		Path:               p.path,
		Kind:               header.ContentType.Label(),
		Format:             header.Format.Label(),
		Version:            stats.Version,
		PageBytes:          stats.PageBytes,
		Encryption:         header.CryptLabel(),
		FileBytes:          stats.FileEOF,
		Nodes:              stats.NodeCount,
		Blocks:             stats.BlockCount,
		FreeNodes:          stats.FreeNodeCount,
		FreeBlocks:         stats.FreeBlockCount,
		Folders:            stats.FolderNodes,
		Messages:           stats.MessageNodes,
		AssociatedMessages: stats.AssociatedMessageNodes,
		ChecksumMismatches: stats.ChecksumMismatches,
	}
}

// Folders returns every folder.
func (p *PSTFile) Folders(ctx context.Context) ([]PSTFolder, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := p.reader.Folders()
	if err != nil {
		return nil, err
	}
	out := make([]PSTFolder, 0, len(raw))
	for _, folder := range raw {
		entry := PSTFolder{
			NID:          folder.NID,
			Parent:       folder.Parent,
			ContentCount: folder.ContentCount,
			MessageCount: folder.MessageCount,
			ChildFolders: append([]uint64(nil), folder.ChildFolders...),
			DataBID:      folder.DataBID,
			DataOffset:   folder.DataOffset,
			SubnodeBID:   folder.SubnodeBID,
			PageOffset:   folder.PageOffset,
		}
		if folder.Name != nil {
			entry.Name = *folder.Name
		}
		out = append(out, entry)
	}
	return out, nil
}

// Messages returns every message with its attachments and recipients.
func (p *PSTFile) Messages(ctx context.Context) ([]PSTMessage, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := p.reader.Messages()
	if err != nil {
		return nil, err
	}
	out := make([]PSTMessage, 0, len(raw))
	for _, message := range raw {
		out = append(out, p.convertMessage(message))
	}
	return out, nil
}

// Message returns one message by NID.
func (p *PSTFile) Message(ctx context.Context, nid uint64) (*PSTMessage, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	message, err := p.reader.Message(nid)
	if err != nil {
		return nil, err
	}
	converted := p.convertMessage(message)
	return &converted, nil
}

func (p *PSTFile) convertMessage(message pst.Message) PSTMessage {
	entry := PSTMessage{
		NID:            message.NID,
		Folder:         message.Folder,
		Associated:     message.Associated,
		Size:           message.Size,
		Flags:          message.Flags,
		HTMLBytes:      len(message.HTML),
		RTFBytes:       len(message.RTF),
		DisplayTo:      append([]string(nil), message.DisplayTo...),
		DisplayCc:      append([]string(nil), message.DisplayCc...),
		DisplayBcc:     append([]string(nil), message.DisplayBcc...),
		HasAttachments: message.HasAttachments,
		DataBID:        message.DataBID,
		DataOffset:     message.DataOffset,
		SubnodeBID:     message.SubnodeBID,
		PageOffset:     message.PageOffset,
	}
	assign := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	assign(&entry.Subject, message.Subject)
	assign(&entry.SenderName, message.SenderName)
	assign(&entry.SenderEmail, message.SenderEmail)
	assign(&entry.MessageClass, message.MessageClass)
	assign(&entry.TransportHeaders, message.TransportHeaders)
	assign(&entry.MessageID, message.MessageID)
	if message.Body != nil {
		entry.Body = *message.Body
		entry.HasBody = true
	}
	if message.SubmitTime != nil {
		entry.SubmitTime = message.SubmitTime.Time()
		entry.HasSubmitTime = !entry.SubmitTime.IsZero()
	}
	if message.DeliveryTime != nil {
		entry.DeliveryTime = message.DeliveryTime.Time()
		entry.HasDeliveryTime = !entry.DeliveryTime.IsZero()
	}
	if attachments, present, err := p.reader.Attachments(message.NID); err == nil && present {
		for _, attachment := range attachments {
			item := PSTAttachment{
				Index:        attachment.Index,
				NID:          attachment.NID,
				Method:       attachment.Method,
				ContentID:    "",
				ObjectBID:    attachment.ObjectBID,
				ObjectOffset: attachment.ObjectOffset,
				Embedded:     attachment.Embedded != nil,
			}
			assign(&item.Filename, attachment.Filename)
			assign(&item.Extension, attachment.Extension)
			assign(&item.MIMEType, attachment.MIMEType)
			assign(&item.ContentID, attachment.ContentID)
			assign(&item.Path, attachment.Path)
			if attachment.Size != nil {
				item.Size = uint64(*attachment.Size)
				item.HasSize = true
			}
			if attachment.DataBytes != nil {
				item.Size = *attachment.DataBytes
				item.HasSize = true
			}
			if attachment.SHA256 != nil {
				item.SHA256 = *attachment.SHA256
			}
			if attachment.DataProblem != nil {
				item.Problem = *attachment.DataProblem
			}
			entry.Attachments = append(entry.Attachments, item)
		}
	}
	if recipients, present, err := p.reader.Recipients(message.NID); err == nil && present {
		for _, recipient := range recipients {
			item := PSTRecipient{
				Index: recipient.Index,
				RowID: recipient.RowID,
				Kind:  recipient.Kind,
			}
			assign(&item.DisplayName, recipient.DisplayName)
			assign(&item.AddressType, recipient.AddressType)
			assign(&item.Email, recipient.Email)
			assign(&item.SMTP, recipient.SMTP)
			if recipient.Problem != nil {
				item.Problem = *recipient.Problem
			}
			entry.Recipients = append(entry.Recipients, item)
		}
	}
	return entry
}

// Close releases the store's file handle. It is idempotent.
func (p *PSTFile) Close() error {
	if p.closer == nil {
		return nil
	}
	err := p.closer.Close()
	p.closer = nil
	return err
}
