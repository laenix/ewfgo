package internal

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func (e *EWFImage) IsEWFFile() bool {
	file, err := os.Open(e.filepath)
	if err != nil {
		return false
	}

	header := make([]byte, 13)
	if _, err := file.Read(header); err != nil {
		return false
	}
	file.Close()
	return bytes.Equal(header[:8], EVFSignature[:])
}

func (e *EWFImage) Open(file string) (*EWFImage, error) {
	e.filepath = file
	// 判断是否为WEF文件签名
	if !e.IsEWFFile() {
		return nil, errors.New("not ewf file")
	}
	//
	return e, nil
}

// 读取某位置的多少个字节
func (e *EWFImage) ReadAt(addr int64, length int64) []byte {
	file, err := os.Open(e.filepath)
	if err != nil {
		return nil
	}
	buffer := make([]byte, length)
	file.ReadAt(buffer, addr)
	return buffer
}

// func (e *EWFImage) ReadHeader(){

// }

func (e *EWFImage) ReadSection(address int64) (*Section, error) {
	// fmt.Println("[*]debug read section ", address)
	section := &Section{}
	buf := e.ReadAt(address, SectionLength)
	var err error
	if buf != nil {
		err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, section)
	}
	return section, err
}

func (e *EWFImage) ReadSections() error {
	// var sections []SectionWithAddress
	address := EWFFileHeaderLength

	for {
		section, err := e.ReadSection(address)
		if err != nil {
			return err
		}
		e.Sections = append(e.Sections, SectionWithAddress{
			Address: address,
			Section: *section,
		})
		address = int64(section.NextOffset)
		if string(bytes.TrimRight(section.SectionTypeDefinition[:], "\x00")) == "done" {
			break
		}
		if section.NextOffset == 0 {
			break
		}
	}
	return nil
}

func (e *EWFImage) ParseSections() error {
	for _, v := range e.Sections {
		switch string(bytes.TrimRight(v.SectionTypeDefinition[:], "\x00")) {
		case "header2":
			e.ParseHeader(v)
		case "header":
			e.ParseHeader(v)
		case "volume":
			e.ParseVolume(v)
		case "disk":
			e.ParseVolume(v)
		case "data":
			fmt.Println("data")
		case "sectors":
			e.AddSectorsAddress(v)
		case "table":
			e.AddTableAddress(v)
		case "table2":
			e.ParseTable2(v)
		case "next":
			fmt.Println("next")
		case "ltype":
			fmt.Println("ltype")
		case "ltree":
			fmt.Println("ltree")
		case "map":
			fmt.Println("map")
		case "error2":
			fmt.Println("error2")
		case "digest":
			fmt.Println("digest")
		case "hash":
			fmt.Println("hash")
		case "done":
			fmt.Println("done")
		}
	}

	for k, v := range e.SectorsAddress {
		tableEntry, err := e.ParseTable(e.TableAddress[k])
		if err != nil {
			return err
		}
		e.Sectors = append(e.Sectors, SectorAndTableWithAddress{
			Address:    v.Address,
			TableEntry: tableEntry,
		})
	}
	return nil
}

// 3.3 3.4
func (e *EWFImage) ParseHeader(s SectionWithAddress) error {
	// 获取到section
	buf := e.ReadAt(s.Address+SectionLength, int64(s.SectionSize)-SectionLength)
	r, err := zlib.NewReader(bytes.NewReader(buf))
	if err != nil {
		return err
	}
	var header bytes.Buffer
	io.Copy(&header, r)
	defer r.Close()
	var linesdata string
	// BOM
	// UTF-16 BE
	if header.Bytes()[0] == 0xfe && header.Bytes()[1] == 0xff {
		utf16be := unicode.UTF16(unicode.BigEndian, unicode.ExpectBOM)
		decoder := utf16be.NewDecoder()
		utf8Data, _, err := transform.Bytes(decoder, header.Bytes())
		if err == nil {
			linesdata = string(utf8Data)
		}
	}
	// UTF-16 LE
	if header.Bytes()[0] == 0xff && header.Bytes()[1] == 0xfe {
		utf16le := unicode.UTF16(unicode.LittleEndian, unicode.ExpectBOM)
		decoder := utf16le.NewDecoder()
		utf8Data, _, err := transform.Bytes(decoder, header.Bytes())
		if err == nil {
			linesdata = string(utf8Data)
		}
	}
	// UTF-32
	if header.Bytes()[0] == 0x00 && header.Bytes()[1] == 0x00 && header.Bytes()[2] == 0xfe && header.Bytes()[3] == 0xff {
	}
	// UTF-32
	if header.Bytes()[0] == 0xff && header.Bytes()[1] == 0xfe && header.Bytes()[2] == 0x00 && header.Bytes()[3] == 0x00 {
	}
	// UTF-8
	if linesdata == "" {
		linesdata = header.String()
	}
	lines := strings.Split(linesdata, "\n")
	var flags []string
	var values []string
	flags = append(flags, strings.Split(lines[2], "\t")...)
	values = append(values, strings.Split(lines[3], "\t")...)

	if len(flags) == len(values) {
		headerSectionString := HeaderSectionString{}
		for k, flag := range flags {
			switch flag {
			case "a":
				headerSectionString.L3_a = values[k]
			case "c":
				headerSectionString.L3_c = values[k]
			case "n":
				headerSectionString.L3_n = values[k]
			case "e":
				headerSectionString.L3_e = values[k]
			case "t":
				headerSectionString.L3_t = values[k]
			case "av":
				headerSectionString.L3_av = values[k]
			case "ov":
				headerSectionString.L3_ov = values[k]
			case "m":
				headerSectionString.L3_m = values[k]
			case "u":
				headerSectionString.L3_u = values[k]
			case "p":
				headerSectionString.L3_p = values[k]
			case "md":
				headerSectionString.L3_md = values[k]
			case "sn":
				headerSectionString.L3_sn = values[k]
			case "l":
				headerSectionString.L3_l = values[k]
			case "pid":
				headerSectionString.L3_pid = values[k]
			case "dc":
				headerSectionString.L3_dc = values[k]
			case "ext":
				headerSectionString.L3_ext = values[k]
			}
		}
		e.Headers = append(e.Headers, headerSectionString)
	}
	return nil
}

// 3.5 Volume
func (e *EWFImage) ParseVolume(s SectionWithAddress) error {
	var buf []byte
	var err error
	// EWFSpecification 94 bytes
	if s.SectionSize > uint64(SectionLength)+uint64(DiskSMARTLength) {
		var ewfSpecification EWFSpecification
		buf = e.ReadAt(s.Address+SectionLength, EWFSpecificationLength)
		if buf != nil {
			err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &ewfSpecification)
		}
		if err != nil {
			return err
		}
		e.Volumes = append(e.Volumes, ewfSpecification)
	}
	// SMART 1052 bytes
	if s.SectionSize == uint64(SectionLength)+uint64(DiskSMARTLength) {
		var diskSMART DiskSMART
		buf = e.ReadAt(s.Address+SectionLength, DiskSMARTLength)
		if buf != nil {
			err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &diskSMART)
		}
		if err != nil {
			return err
		}
		e.DiskSMART = append(e.DiskSMART, diskSMART)
	}
	return err
}

// 3.6 Disk
func (e *EWFImage) ParseDisk(s SectionWithAddress) {

}

// 3.7 Data
func (e *EWFImage) ParseData(s SectionWithAddress) {

}

// 3.8 Sector
func (e *EWFImage) AddSectorsAddress(s SectionWithAddress) error {
	// fmt.Println("[*] debug from AddSectorsAddress at", s.Address)
	e.SectorsAddress = append(e.SectorsAddress, s)
	return nil
}

func (e *EWFImage) ParseSectors(s SectionWithAddress) (io.ReadCloser, error) {
	// fmt.Println("[*]debug sectors read at", s.Address)
	// buf := e.ReadAt(s.Address+SectionLength, int64(s.SectionSize)-SectionLength)
	// r, err := zlib.NewReader(bytes.NewReader(buf))
	// // 未压缩
	// if err != nil {
	// 	r = io.NopCloser(bytes.NewReader(buf))
	// 	return r, nil
	// }
	// // var out bytes.Buffer
	// // io.CopyN(&out, r, 64)
	// // defer r.Close()
	// // fmt.Println(out.Bytes())
	return nil, nil
}

// 3.9 Table
func (e *EWFImage) AddTableAddress(s SectionWithAddress) error {
	// fmt.Println("[*] debug from AddTableAddress at", s.Address)
	e.TableAddress = append(e.TableAddress, s)
	return nil
}

func (e *EWFImage) ParseTable(s SectionWithAddress) ([]uint32, error) {
	// fmt.Println("[*]debug read table at", s.Address)
	tableHeaderBuf := e.ReadAt(s.Address+SectionLength, TableSectionLength)
	var tableHeader TableSection
	err := binary.Read(bytes.NewReader(tableHeaderBuf), binary.LittleEndian, &tableHeader)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("表项数: %d\n", tableHeader.EntryNumber)

	buf := e.ReadAt(s.Address+SectionLength+TableSectionLength, int64(s.SectionSize)-SectionLength-TableSectionLength)
	len := ((int64(s.SectionSize) - SectionLength - TableSectionLength) / 4) - 1
	tableEntry := make([]uint32, len)
	err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &tableEntry)
	if err != nil {
		return nil, err
	}
	for k, entry := range tableEntry {
		tableEntry[k] = entry & 0x7FFFFFFF
	}
	return tableEntry, nil
}

// 3.10 Table2
func (e *EWFImage) ParseTable2(s SectionWithAddress) error {
	// fmt.Println("[*]debug read table2 at", s.Address)
	// buf := e.ReadAt(s.Address+SectionLength, int64(s.SectionSize)-SectionLength)
	// fmt.Println(buf[:64])
	// fmt.Println(s.SectionSize)
	return nil
}

// 3.11 Next
func (e *EWFImage) ParsesNext(s SectionWithAddress) {

}

// 3.12 Ltype
func (e *EWFImage) ParsesLtype(s SectionWithAddress) {

}

// 3.13 Ltree
func (e *EWFImage) ParsesLtree(s SectionWithAddress) {

}

// 3.14 Map
func (e *EWFImage) ParsesMap(s SectionWithAddress) {

}

// 3.15 Session
func (e *EWFImage) ParsesSession(s SectionWithAddress) {

}

// 3.16 Error2
func (e *EWFImage) ParsesError2(s SectionWithAddress) {

}

// 3.17 Digest
func (e *EWFImage) ParsesDigest(s SectionWithAddress) {

}

// 3.18 Hash
func (e *EWFImage) ParsesHash(s SectionWithAddress) {

}

// 3.19 Done
func (e *EWFImage) ParsesDone(s SectionWithAddress) {

}
