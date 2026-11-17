package l01

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

const maxHeaderTextBytes = 16 * 1024 * 1024

// inflateHeaderIfZlib recognises a zlib stream even when the descriptor does
// not name the method. EnCase commonly stores `header2` compressed; a raw
// `header` text does not start with the 0x78 CMF byte.
func inflateHeaderIfZlib(data []byte) ([]byte, bool) {
	if len(data) < 2 || data[0] != 0x78 {
		return nil, false
	}
	if (uint16(data[0])<<8|uint16(data[1]))%31 != 0 {
		return nil, false
	}
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	payload, readErr := io.ReadAll(io.LimitReader(reader, maxHeaderTextBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(payload) == 0 || len(payload) > maxHeaderTextBytes {
		return nil, false
	}
	return payload, true
}

// readHeaderMetadata parses the first non-empty EWF `header`/`header2`
// section. Metadata is advisory: a malformed section produces a warning and
// leaves the fields empty rather than failing a catalog that is otherwise
// readable.
func readHeaderMetadata(segments []segment, warnings *[]string) Header {
	for _, segment := range segments {
		for _, section := range segment.sections {
			if section.kind != "header" && section.kind != "header2" {
				continue
			}
			if section.dataSize == 0 {
				continue
			}
			data, err := source.ReadVecAt(segment.source, section.dataOffset, section.dataSize)
			if err != nil {
				*warnings = append(*warnings, fmt.Sprintf(
					"header section at %d could not be read: %v", section.dataOffset, err))
				continue
			}
			return parseHeaderPayload(data, section.compressionMethod, warnings)
		}
	}
	return Header{}
}

func parseHeaderPayload(data []byte, method string, warnings *[]string) Header {
	payload := data
	switch method {
	case "zlib":
		reader, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf(
				"header section could not be decompressed: %v", err))
			return Header{}
		}
		payload, err = io.ReadAll(io.LimitReader(reader, maxHeaderTextBytes+1))
		closeErr := reader.Close()
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf(
				"header section could not be decompressed: %v", err))
			return Header{}
		}
		if closeErr != nil {
			*warnings = append(*warnings, fmt.Sprintf(
				"header section decompression ended with an error: %v", closeErr))
		}
		if len(payload) > maxHeaderTextBytes {
			*warnings = append(*warnings, fmt.Sprintf(
				"header section exceeds the %d-byte text bound", maxHeaderTextBytes))
			return Header{}
		}
	case "deflate":
		reader := flate.NewReader(bytes.NewReader(data))
		var err error
		payload, err = io.ReadAll(io.LimitReader(reader, maxHeaderTextBytes+1))
		closeErr := reader.Close()
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf(
				"header section could not be decompressed: %v", err))
			return Header{}
		}
		if closeErr != nil {
			*warnings = append(*warnings, fmt.Sprintf(
				"header section decompression ended with an error: %v", closeErr))
		}
		if len(payload) > maxHeaderTextBytes {
			*warnings = append(*warnings, fmt.Sprintf(
				"header section exceeds the %d-byte text bound", maxHeaderTextBytes))
			return Header{}
		}
	}

	if method == "" {
		if inflated, ok := inflateHeaderIfZlib(payload); ok {
			payload = inflated
		}
	}

	text := decodeHeaderText(payload)
	lines := strings.Split(text, "\n")
	for index := range lines {
		lines[index] = strings.TrimSuffix(lines[index], "\r")
	}
	if len(lines) < 4 {
		*warnings = append(*warnings, fmt.Sprintf(
			"header section is malformed: got %d lines, need at least 4", len(lines)))
		return Header{}
	}
	flags := strings.Split(lines[2], "\t")
	values := strings.Split(lines[3], "\t")
	if len(flags) != len(values) {
		*warnings = append(*warnings, fmt.Sprintf(
			"header section is malformed: %d field indicators for %d values", len(flags), len(values)))
		return Header{}
	}

	var header Header
	for index, flag := range flags {
		if index >= len(values) {
			break
		}
		value := values[index]
		switch flag {
		case "a":
			header.Description = value
		case "c":
			header.CaseNumber = value
		case "n":
			header.EvidenceNumber = value
		case "e":
			header.Examiner = value
		case "t":
			header.Notes = value
		case "av":
			header.AcquisitionSoftware = value
		case "ov":
			header.AcquisitionOS = value
		case "m":
			header.AcquisitionDate = value
		case "u":
			header.SystemDate = value
		case "md":
			header.Model = value
		case "sn":
			header.SerialNumber = value
		case "l":
			header.DeviceLabel = value
		case "pid":
			header.ProcessID = value
		}
	}
	return header
}

func decodeHeaderText(payload []byte) string {
	if len(payload) >= 2 {
		switch {
		case payload[0] == 0xff && payload[1] == 0xfe:
			return decodeUTF16(payload[2:], binary.LittleEndian)
		case payload[0] == 0xfe && payload[1] == 0xff:
			return decodeUTF16(payload[2:], binary.BigEndian)
		}
	}
	return string(payload)
}

func decodeUTF16(data []byte, order binary.ByteOrder) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	units := make([]uint16, len(data)/2)
	for index := range units {
		units[index] = order.Uint16(data[index*2:])
	}
	return string(utf16.Decode(units))
}
