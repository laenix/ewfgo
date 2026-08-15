package nbd_test

// Hermetic wire-level tests for the pure-Go NBD server. Every test drives the
// server over an in-memory net.Pipe — no real port, no external client, no
// subprocesses. The client side of each test is written directly against the
// NBD newstyle protocol wire values from the task brief (task-18-brief.md), so
// the assertions verify the exact bytes on the wire, independent of the server
// package's internal constant names.
//
// TestNBD_RealE01Fixture proves the EWF red line end-to-end: sector data served
// over NBD comes from the exact-decompression path (ewf.Open +
// EWFImage.ReadSectors), never fabricated bytes.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	ewf "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/ewffixture"
	"github.com/laenix/ewfgo/nbd"
)

// --- client-side wire helpers (newstyle NBD, values from the brief) ---

const (
	magicNBDMAGIC uint64 = 0x4e42444d41474943 // "NBDMAGIC"
	magicIHAVEOPT uint64 = 0x49484156454f5054 // "IHAVEOPT"
	magicREP      uint64 = 0x0003e889045565a9 // "NBD_REP_MAGIC"
	magicREQUEST  uint32 = 0x25609513
	magicREPLY    uint32 = 0x67446698

	repACK      uint32 = 1
	repServer   uint32 = 2
	repInfo     uint32 = 3
	repErrUnsup uint32 = 0x80000001

	optExportName      uint32 = 1
	optAbort           uint32 = 2
	optList            uint32 = 3
	optInfo            uint32 = 6
	optGO              uint32 = 7
	optStructuredReply uint32 = 8

	cmdRead        uint16 = 0
	cmdWrite       uint16 = 1
	cmdDisc        uint16 = 2
	cmdFlush       uint16 = 3
	cmdTrim        uint16 = 4
	cmdCache       uint16 = 5
	cmdWriteZeroes uint16 = 6
	cmdBlockStatus uint16 = 7

	errnoEPERM  uint32 = 1
	errnoEIO    uint32 = 5
	errnoEINVAL uint32 = 22

	// Transmission flags the server must advertise (read-only forensic export).
	wantXmitFlags uint16 = 0x0007
)

// startServer runs srv.Serve() over a net.Pipe in a goroutine and returns the
// client end plus a buffered channel carrying Serve()'s return value.
func startServer(t *testing.T, exp nbd.Exporter, name string) (net.Conn, chan error) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	srv := nbd.NewServer(serverConn, exp, name)
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	return clientConn, done
}

// readNBD reads exactly n bytes, failing the test on a short read.
func readNBD(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// writeNBD writes all of b, failing the test on a short write.
func writeNBD(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// handshake performs the client side of the newstyle handshake: reads the
// server greeting and asserts the exact magics and handshake flags, then sends
// the given client flags.
func handshake(t *testing.T, c net.Conn, clientFlags uint32) {
	t.Helper()
	g := readNBD(t, c, 18)
	if got := binary.BigEndian.Uint64(g[0:8]); got != magicNBDMAGIC {
		t.Fatalf("handshake NBDMAGIC = %#x, want %#x", got, magicNBDMAGIC)
	}
	if got := binary.BigEndian.Uint64(g[8:16]); got != magicIHAVEOPT {
		t.Fatalf("handshake IHAVEOPT = %#x, want %#x", got, magicIHAVEOPT)
	}
	if got := binary.BigEndian.Uint16(g[16:18]); got != 0x0003 {
		t.Fatalf("handshake flags = %#x, want 0x0003 (FIXED_NEWSTYLE|NO_ZEROES)", got)
	}
	var cf [4]byte
	binary.BigEndian.PutUint32(cf[:], clientFlags)
	writeNBD(t, c, cf[:])
}

// sendOption sends an option: IHAVEOPT magic + option code + length + payload.
func sendOption(t *testing.T, c net.Conn, code uint32, payload []byte) {
	t.Helper()
	var hdr [16]byte
	binary.BigEndian.PutUint64(hdr[0:8], magicIHAVEOPT)
	binary.BigEndian.PutUint32(hdr[8:12], code)
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(payload)))
	writeNBD(t, c, hdr[:])
	if len(payload) > 0 {
		writeNBD(t, c, payload)
	}
}

// readOptionReply reads an option reply header + payload and asserts the reply
// magic. It returns the echoed option code, the reply type, and the payload.
func readOptionReply(t *testing.T, c net.Conn) (code uint32, reply uint32, payload []byte) {
	t.Helper()
	hdr := readNBD(t, c, 20)
	if got := binary.BigEndian.Uint64(hdr[0:8]); got != magicREP {
		t.Fatalf("option reply magic = %#x, want %#x", got, magicREP)
	}
	code = binary.BigEndian.Uint32(hdr[8:12])
	reply = binary.BigEndian.Uint32(hdr[12:16])
	length := binary.BigEndian.Uint32(hdr[16:20])
	if length > 0 {
		payload = readNBD(t, c, int(length))
	}
	return code, reply, payload
}

// sendRequest sends a transmission-phase request.
func sendRequest(t *testing.T, c net.Conn, typ uint16, handle uint64, offset uint64, length uint32) {
	t.Helper()
	var req [28]byte
	binary.BigEndian.PutUint32(req[0:4], magicREQUEST)
	binary.BigEndian.PutUint16(req[4:6], 0) // command flags: 0
	binary.BigEndian.PutUint16(req[6:8], typ)
	binary.BigEndian.PutUint64(req[8:16], handle)
	binary.BigEndian.PutUint64(req[16:24], offset)
	binary.BigEndian.PutUint32(req[24:28], length)
	writeNBD(t, c, req[:])
}

// readRequestReply reads a transmission-phase simple reply, asserting the reply
// magic, and returns the error code, echoed handle, and payloadLen payload
// bytes (the simple reply header carries no length, so the caller supplies it).
func readRequestReply(t *testing.T, c net.Conn, payloadLen int) (errCode uint32, handle uint64, payload []byte) {
	t.Helper()
	hdr := readNBD(t, c, 16)
	if got := binary.BigEndian.Uint32(hdr[0:4]); got != magicREPLY {
		t.Fatalf("request reply magic = %#x, want %#x", got, magicREPLY)
	}
	errCode = binary.BigEndian.Uint32(hdr[4:8])
	handle = binary.BigEndian.Uint64(hdr[8:16])
	if payloadLen > 0 {
		payload = readNBD(t, c, payloadLen)
	}
	return errCode, handle, payload
}

// goExport is a client helper for the common "handshake + NBD_OPT_GO(name)"
// path that leaves the server in the transmission phase. It asserts the
// NBD_REP_INFO and NBD_REP_ACK replies, including the NBD_INFO_EXPORT info
// type (0) and the export size the server advertises.
func goExport(t *testing.T, c net.Conn, name string, wantSize uint64) {
	t.Helper()
	sendOption(t, c, optGO, []byte(name))
	code, reply, payload := readOptionReply(t, c)
	if code != optGO {
		t.Fatalf("GO reply echoed code = %d, want %d", code, optGO)
	}
	if reply != repInfo {
		t.Fatalf("GO first reply = %d, want NBD_REP_INFO(%d)", reply, repInfo)
	}
	if len(payload) != 12 {
		t.Fatalf("GO INFO payload len = %d, want 12", len(payload))
	}
	if infoType := binary.BigEndian.Uint16(payload[0:2]); infoType != 0 {
		t.Fatalf("NBD_INFO type = %d, want 0 (NBD_INFO_EXPORT)", infoType)
	}
	if size := binary.BigEndian.Uint64(payload[2:10]); size != wantSize {
		t.Fatalf("NBD_INFO export size = %d, want %d", size, wantSize)
	}
	if flags := binary.BigEndian.Uint16(payload[10:12]); flags != wantXmitFlags {
		t.Fatalf("NBD_INFO transmission flags = %#x, want %#x", flags, wantXmitFlags)
	}
	code, reply, payload = readOptionReply(t, c)
	if code != optGO || reply != repACK || len(payload) != 0 {
		t.Fatalf("GO ACK: code=%d reply=%d payloadLen=%d, want code=%d reply=%d len=0",
			code, reply, len(payload), optGO, repACK)
	}
}

// disc is a client helper that ends a session cleanly and asserts Serve()
// returns without error.
func disc(t *testing.T, c net.Conn, done chan error) {
	t.Helper()
	sendRequest(t, c, cmdDisc, 0xdecafbadcafe, 0, 0)
	if err := <-done; err != nil {
		t.Fatalf("Serve() after DISC = %v, want nil", err)
	}
}

// memoryExporter is a tiny in-memory Exporter for the protocol tests.
type memoryExporter struct {
	data []byte
}

func (m *memoryExporter) Size() uint64 { return uint64(len(m.data)) }

func (m *memoryExporter) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// pattern returns n deterministic non-zero bytes.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*7 + 3) & 0xff)
	}
	return b
}

// --- tests ---

// TestNBD_Handshake performs the newstyle handshake and an NBD_OPT_EXPORT_NAME,
// asserting the export size, the read-only transmission flags (0x0007) and the
// 124 zero padding bytes (client did not set NO_ZEROES).
func TestNBD_Handshake(t *testing.T) {
	data := pattern(1024)
	c, done := startServer(t, &memoryExporter{data: data}, "test")

	handshake(t, c, 0x0001) // NBD_FLAG_C_FIXED_NEWSTYLE only (NO_ZEROES unset)

	sendOption(t, c, optExportName, []byte("test"))
	// EXPORT_NAME reply has no option-reply header: 8-byte size + 2-byte flags
	// + 124 zero bytes (NO_ZEROES not negotiated).
	rsp := readNBD(t, c, 8+2+124)
	if size := binary.BigEndian.Uint64(rsp[0:8]); size != 1024 {
		t.Fatalf("export size = %d, want 1024", size)
	}
	if flags := binary.BigEndian.Uint16(rsp[8:10]); flags != wantXmitFlags {
		t.Fatalf("transmission flags = %#x, want %#x", flags, wantXmitFlags)
	}
	for i := 10; i < len(rsp); i++ {
		if rsp[i] != 0 {
			t.Fatalf("EXPORT_NAME padding byte %d = %d, want 0", i, rsp[i])
		}
	}

	// Transmission phase: the export serves the exact pattern bytes.
	sendRequest(t, c, cmdRead, 0x1111, 0, 512)
	errCode, handle, payload := readRequestReply(t, c, 512)
	if errCode != 0 || handle != 0x1111 {
		t.Fatalf("READ err=%d handle=%#x, want 0/0x1111", errCode, handle)
	}
	if !bytes.Equal(payload, data[:512]) {
		t.Fatal("READ returned wrong bytes after EXPORT_NAME")
	}
	disc(t, c, done)
}

// TestNBD_Handshake_NoZeroes asserts that when the client negotiates
// NO_ZEROES, the EXPORT_NAME reply omits the 124 zero padding bytes.
func TestNBD_Handshake_NoZeroes(t *testing.T) {
	data := pattern(1024)
	c, done := startServer(t, &memoryExporter{data: data}, "test")

	handshake(t, c, 0x0003) // FIXED_NEWSTYLE | NO_ZEROES
	sendOption(t, c, optExportName, []byte(""))
	rsp := readNBD(t, c, 8+2)
	if size := binary.BigEndian.Uint64(rsp[0:8]); size != 1024 {
		t.Fatalf("export size = %d, want 1024", size)
	}
	if flags := binary.BigEndian.Uint16(rsp[8:10]); flags != wantXmitFlags {
		t.Fatalf("transmission flags = %#x, want %#x", flags, wantXmitFlags)
	}
	disc(t, c, done)
}

// TestNBD_OptionNegotiation exercises the option loop: an unknown option must
// get NBD_REP_ERR_UNSUP, then NBD_OPT_GO must reply NBD_REP_INFO (export info)
// followed by NBD_REP_ACK and enter the transmission phase.
func TestNBD_OptionNegotiation(t *testing.T) {
	data := pattern(1024)
	c, done := startServer(t, &memoryExporter{data: data}, "test")

	handshake(t, c, 0x0003)

	// Unknown option code 999 -> NBD_REP_ERR_UNSUP, echoed code.
	sendOption(t, c, 999, nil)
	code, reply, payload := readOptionReply(t, c)
	if code != 999 {
		t.Fatalf("unknown option echoed code = %d, want 999", code)
	}
	if reply != repErrUnsup {
		t.Fatalf("unknown option reply = %d, want NBD_REP_ERR_UNSUP(%d)", reply, repErrUnsup)
	}
	if len(payload) != 0 {
		t.Fatalf("ERR_UNSUP payload len = %d, want 0", len(payload))
	}

	// NBD_OPT_STRUCTURED_REPLY is not supported either.
	sendOption(t, c, optStructuredReply, nil)
	code, reply, _ = readOptionReply(t, c)
	if code != optStructuredReply || reply != repErrUnsup {
		t.Fatalf("STRUCTURED_REPLY: code=%d reply=%d, want code=%d reply=%d",
			code, reply, optStructuredReply, repErrUnsup)
	}

	// NBD_OPT_GO -> NBD_REP_INFO + NBD_REP_ACK, then transmission.
	goExport(t, c, "test", 1024)
	sendRequest(t, c, cmdRead, 0x2222, 0, 512)
	errCode, handle, payload := readRequestReply(t, c, 512)
	if errCode != 0 || handle != 0x2222 {
		t.Fatalf("READ err=%d handle=%#x, want 0/0x2222", errCode, handle)
	}
	if !bytes.Equal(payload, data[:512]) {
		t.Fatal("READ returned wrong bytes after GO")
	}
	disc(t, c, done)
}

// TestNBD_List asserts NBD_OPT_LIST replies NBD_REP_SERVER (export name) then
// NBD_REP_ACK, without leaving negotiation.
func TestNBD_List(t *testing.T) {
	c, done := startServer(t, &memoryExporter{data: pattern(512)}, "my-export")

	handshake(t, c, 0x0003)
	sendOption(t, c, optList, nil)

	code, reply, payload := readOptionReply(t, c)
	if code != optList || reply != repServer {
		t.Fatalf("LIST: code=%d reply=%d, want code=%d reply=%d", code, reply, optList, repServer)
	}
	if len(payload) < 4 {
		t.Fatalf("LIST SERVER payload len = %d, want >= 4", len(payload))
	}
	nameLen := binary.BigEndian.Uint32(payload[0:4])
	name := string(payload[4:])
	if nameLen != uint32(len(name)) || name != "my-export" {
		t.Fatalf("LIST SERVER name = %q (len %d), want %q", name, nameLen, "my-export")
	}

	code, reply, payload = readOptionReply(t, c)
	if code != optList || reply != repACK || len(payload) != 0 {
		t.Fatalf("LIST ACK: code=%d reply=%d payloadLen=%d, want ACK empty", code, reply, len(payload))
	}

	// Still in negotiation: a GO works.
	goExport(t, c, "", 512)
	disc(t, c, done)
}

// TestNBD_Abort asserts NBD_OPT_ABORT is answered with NBD_REP_ACK and the
// connection closes cleanly (Serve returns nil).
func TestNBD_Abort(t *testing.T) {
	c, done := startServer(t, &memoryExporter{data: pattern(512)}, "test")

	handshake(t, c, 0x0003)
	sendOption(t, c, optAbort, nil)

	code, reply, payload := readOptionReply(t, c)
	if code != optAbort || reply != repACK || len(payload) != 0 {
		t.Fatalf("ABORT: code=%d reply=%d payloadLen=%d, want ACK empty", code, reply, len(payload))
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve() after ABORT = %v, want nil", err)
	}
	// Connection is closed: the client end reads EOF.
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after ABORT client read = %v, want io.EOF", err)
	}
}

// TestNBD_Read reads a sector-aligned range and a non-sector-aligned range and
// asserts the exact bytes are served, plus a zero-length read succeeding.
func TestNBD_Read(t *testing.T) {
	data := pattern(1024)
	c, done := startServer(t, &memoryExporter{data: data}, "test")

	handshake(t, c, 0x0003)
	goExport(t, c, "", 1024)

	// Sector-aligned READ (offset 0, length 512).
	sendRequest(t, c, cmdRead, 0xaaaa0001, 0, 512)
	errCode, handle, payload := readRequestReply(t, c, 512)
	if errCode != 0 || handle != 0xaaaa0001 {
		t.Fatalf("READ(0,512) err=%d handle=%#x, want 0/0xaaaa0001", errCode, handle)
	}
	if !bytes.Equal(payload, data[:512]) {
		t.Fatal("READ(0,512) served wrong bytes")
	}

	// Non-sector-aligned READ (offset 10, length 100).
	sendRequest(t, c, cmdRead, 0xaaaa0002, 10, 100)
	errCode, handle, payload = readRequestReply(t, c, 100)
	if errCode != 0 || handle != 0xaaaa0002 {
		t.Fatalf("READ(10,100) err=%d handle=%#x, want 0/0xaaaa0002", errCode, handle)
	}
	if !bytes.Equal(payload, data[10:110]) {
		t.Fatalf("READ(10,100) = %x, want %x", payload, data[10:110])
	}

	// Zero-length READ succeeds with no payload.
	sendRequest(t, c, cmdRead, 0xaaaa0003, 0, 0)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != 0 {
		t.Fatalf("READ(0,0) err = %d, want 0", errCode)
	}
	disc(t, c, done)
}

// TestNBD_ReadOutOfRange asserts a READ whose range falls outside the export
// replies EINVAL (22) with no payload and the correct magic/handle — never
// fabricated bytes.
func TestNBD_ReadOutOfRange(t *testing.T) {
	data := pattern(1024) // export size 1024
	c, done := startServer(t, &memoryExporter{data: data}, "test")

	handshake(t, c, 0x0003)
	goExport(t, c, "", 1024)

	// offset 1000 + length 100 = 1100 > 1024 -> EINVAL, no payload.
	sendRequest(t, c, cmdRead, 0xcccc0001, 1000, 100)
	errCode, handle, payload := readRequestReply(t, c, 0)
	if errCode != errnoEINVAL {
		t.Fatalf("out-of-range READ err = %d, want EINVAL(%d)", errCode, errnoEINVAL)
	}
	if handle != 0xcccc0001 {
		t.Fatalf("out-of-range READ handle = %#x, want 0xcccc0001", handle)
	}
	if len(payload) != 0 {
		t.Fatalf("out-of-range READ payload len = %d, want 0", len(payload))
	}

	// offset == size, length 1 -> EINVAL.
	sendRequest(t, c, cmdRead, 0xcccc0002, 1024, 1)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != errnoEINVAL {
		t.Fatalf("READ at size err = %d, want EINVAL(%d)", errCode, errnoEINVAL)
	}

	// offset > size, length 0 -> EINVAL (a zero-length read at offset==size is
	// the only zero-length success; past the end is still an error).
	sendRequest(t, c, cmdRead, 0xcccc0003, 2048, 0)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != errnoEINVAL {
		t.Fatalf("READ past end (len 0) err = %d, want EINVAL(%d)", errCode, errnoEINVAL)
	}
	disc(t, c, done)
}

// TestNBD_ReadOnlyRejectsWrite asserts the write-family commands are answered
// EPERM (1) on the read-only export.
func TestNBD_ReadOnlyRejectsWrite(t *testing.T) {
	c, done := startServer(t, &memoryExporter{data: pattern(1024)}, "test")

	handshake(t, c, 0x0003)
	goExport(t, c, "", 1024)

	// NBD_CMD_WRITE -> EPERM.
	sendRequest(t, c, cmdWrite, 0xdead0001, 0, 512)
	errCode, handle, payload := readRequestReply(t, c, 0)
	if errCode != errnoEPERM || handle != 0xdead0001 {
		t.Fatalf("WRITE err=%d handle=%#x, want EPERM(%d)/0xdead0001", errCode, handle, errnoEPERM)
	}
	if len(payload) != 0 {
		t.Fatalf("WRITE reply payload len = %d, want 0", len(payload))
	}

	// NBD_CMD_TRIM -> EPERM.
	sendRequest(t, c, cmdTrim, 0xdead0002, 0, 512)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != errnoEPERM {
		t.Fatalf("TRIM err = %d, want EPERM(%d)", errCode, errnoEPERM)
	}

	// NBD_CMD_WRITE_ZEROES -> EPERM.
	sendRequest(t, c, cmdWriteZeroes, 0xdead0003, 0, 512)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != errnoEPERM {
		t.Fatalf("WRITE_ZEROES err = %d, want EPERM(%d)", errCode, errnoEPERM)
	}

	// NBD_CMD_CACHE and NBD_CMD_BLOCK_STATUS are not advertised -> EINVAL.
	sendRequest(t, c, cmdCache, 0xdead0004, 0, 512)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != errnoEINVAL {
		t.Fatalf("CACHE err = %d, want EINVAL(%d)", errCode, errnoEINVAL)
	}
	sendRequest(t, c, cmdBlockStatus, 0xdead0005, 0, 512)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != errnoEINVAL {
		t.Fatalf("BLOCK_STATUS err = %d, want EINVAL(%d)", errCode, errnoEINVAL)
	}

	// NBD_CMD_FLUSH succeeds (advertised via SEND_FLUSH).
	sendRequest(t, c, cmdFlush, 0xdead0006, 0, 0)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != 0 {
		t.Fatalf("FLUSH err = %d, want 0", errCode)
	}
	disc(t, c, done)
}

// TestNBD_Disc asserts NBD_CMD_DISC makes Serve() return nil and closes the
// connection (the client end reads EOF).
func TestNBD_Disc(t *testing.T) {
	c, done := startServer(t, &memoryExporter{data: pattern(1024)}, "test")

	handshake(t, c, 0x0003)
	goExport(t, c, "", 1024)

	sendRequest(t, c, cmdDisc, 0xfeed0001, 0, 0)
	if err := <-done; err != nil {
		t.Fatalf("Serve() after DISC = %v, want nil", err)
	}
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after DISC client read = %v, want io.EOF", err)
	}
}

// TestNBD_MalformedMagic asserts a request with a bad magic closes the
// connection (Serve returns an error, client reads EOF) without panicking.
func TestNBD_MalformedMagic(t *testing.T) {
	c, done := startServer(t, &memoryExporter{data: pattern(1024)}, "test")

	handshake(t, c, 0x0003)
	goExport(t, c, "", 1024)

	// A request with the wrong 4-byte magic.
	var req [28]byte
	binary.BigEndian.PutUint32(req[0:4], 0xdeadbeef)
	binary.BigEndian.PutUint16(req[6:8], cmdRead)
	binary.BigEndian.PutUint64(req[16:24], 0)
	binary.BigEndian.PutUint32(req[24:28], 512)
	writeNBD(t, c, req[:])

	if err := <-done; err == nil {
		t.Fatal("Serve() with bad request magic = nil, want an error (connection closed)")
	}
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after bad magic client read = %v, want io.EOF", err)
	}
}

// TestNBD_ShortRequest asserts a truncated request header closes the
// connection without panicking.
func TestNBD_ShortRequest(t *testing.T) {
	c, done := startServer(t, &memoryExporter{data: pattern(1024)}, "test")

	handshake(t, c, 0x0003)
	goExport(t, c, "", 1024)

	// Only 10 bytes of a request header, then EOF.
	writeNBD(t, c, []byte{0x25, 0x60, 0x95, 0x13, 0, 0, 0, 0, 0, 0})
	c.Close()

	if err := <-done; err == nil {
		t.Fatal("Serve() after short request = nil, want an error")
	}
}

// TestNBD_RealE01Fixture proves the EWF red line end-to-end: a tiny E01 built
// with internal/ewffixture is opened with ewf.Open and served over net.Pipe;
// sector 0 must be the exact MBR bytes the fixture embeds, and a read from
// inside the partition must be the exact injected pattern. No fabricated bytes.
func TestNBD_RealE01Fixture(t *testing.T) {
	// A 32-sector partition of 0xAA at LBA 2048 wrapped in an MBR disk, then
	// wrapped into an E01 by the in-repo fixture builder (pure Go, hermetic).
	fsImage := bytes.Repeat([]byte{0xAA}, 32*512)
	disk := ewffixture.WrapMBRDisk(fsImage, 0x0C, 2048) // 2081 sectors total
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	path := filepath.Join(t.TempDir(), "fixture.E01")
	if err := os.WriteFile(path, e01, 0o600); err != nil {
		t.Fatal(err)
	}

	img, err := ewf.Open(path)
	if err != nil {
		t.Fatalf("ewf.Open: %v", err)
	}
	defer img.Close()

	exp := nbd.NewImageExporter(img)
	if want := uint64(2081 * 512); exp.Size() != want {
		t.Fatalf("image export size = %d, want %d", exp.Size(), want)
	}

	c, done := startServer(t, exp, "fixture.E01")
	handshake(t, c, 0x0003)
	goExport(t, c, "", 2081 * 512)

	// READ sector 0 (the MBR): assert the boot signature and the partition
	// entry start LBA / size written by WrapMBRDisk.
	sendRequest(t, c, cmdRead, 0x1234abcd, 0, 512)
	errCode, handle, payload := readRequestReply(t, c, 512)
	if errCode != 0 || handle != 0x1234abcd {
		t.Fatalf("MBR READ err=%d handle=%#x, want 0/0x1234abcd", errCode, handle)
	}
	if payload[510] != 0x55 || payload[511] != 0xAA {
		t.Fatalf("MBR boot signature = %#02x%#02x, want 55 AA", payload[511], payload[510])
	}
	if start := binary.LittleEndian.Uint32(payload[454:458]); start != 2048 {
		t.Fatalf("MBR partition start LBA = %d, want 2048", start)
	}
	if size := binary.LittleEndian.Uint32(payload[458:462]); size != 32 {
		t.Fatalf("MBR partition size = %d sectors, want 32", size)
	}

	// A non-sector-aligned read in the MBR area (offset 10, length 100): exact
	// decompressed bytes, no fabrication.
	sendRequest(t, c, cmdRead, 0x1234abce, 10, 100)
	errCode, _, payload = readRequestReply(t, c, 100)
	if errCode != 0 {
		t.Fatalf("unaligned READ err = %d, want 0", errCode)
	}
	if !bytes.Equal(payload, disk[10:110]) {
		t.Fatal("unaligned READ served wrong decompressed bytes")
	}

	// READ the first sector of the 0xAA partition (image LBA 2048).
	sendRequest(t, c, cmdRead, 0x1234abcf, 2048*512, 512)
	errCode, _, payload = readRequestReply(t, c, 512)
	if errCode != 0 {
		t.Fatalf("partition READ err = %d, want 0", errCode)
	}
	for i, b := range payload {
		if b != 0xAA {
			t.Fatalf("partition sector byte %d = %#x, want 0xAA", i, b)
		}
	}

	// A READ just past the end of the export -> EINVAL, never fabricated bytes.
	sendRequest(t, c, cmdRead, 0x1234abd0, 2081*512, 1)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != errnoEINVAL {
		t.Fatalf("past-end READ err = %d, want EINVAL(%d)", errCode, errnoEINVAL)
	}

	disc(t, c, done)
}

// TestNBD_PartitionExporter_RealFixture exercises the -partition adapter end to
// end against a committed real-filesystem E01: NewPartitionExporter serves the
// partition-relative bytes, so reading offset 0 must return the FAT32 boot
// sector and a read past the partition end must be EINVAL.
func TestNBD_PartitionExporter_RealFixture(t *testing.T) {
	img, err := ewf.Open(filepath.Join("..", "testdata", "e01", "fat32-encase25-zlib.E01"))
	if err != nil {
		t.Fatalf("ewf.Open(fat32 fixture): %v", err)
	}
	defer img.Close()

	fs, err := img.OpenFileSystem(0)
	if err != nil {
		t.Fatalf("OpenFileSystem(0): %v", err)
	}
	defer fs.Close()

	exp := nbd.NewPartitionExporter(fs)
	size := exp.Size()
	if size == 0 {
		t.Fatal("partition export size is 0")
	}

	c, done := startServer(t, exp, "fat32.E01")
	handshake(t, c, 0x0003)
	goExport(t, c, "", size)

	// The partition's first sector is the FAT32 boot sector: "FAT32" at +0x52.
	sendRequest(t, c, cmdRead, 0xbeef0001, 0, 512)
	errCode, _, payload := readRequestReply(t, c, 512)
	if errCode != 0 {
		t.Fatalf("partition boot-sector READ err = %d, want 0", errCode)
	}
	if !bytes.Equal(payload[0x52:0x57], []byte("FAT32")) {
		t.Fatalf("partition boot sector has no FAT32 signature at +0x52: %x", payload[0x52:0x57])
	}

	// READ spanning past the partition end -> EINVAL.
	sendRequest(t, c, cmdRead, 0xbeef0002, size-1, 512)
	errCode, _, _ = readRequestReply(t, c, 0)
	if errCode != errnoEINVAL {
		t.Fatalf("past-end partition READ err = %d, want EINVAL(%d)", errCode, errnoEINVAL)
	}

	disc(t, c, done)
}

// TestNBD_ListenUnix exercises the Unix-domain-socket listener end to end: the
// listener binds a real socket file, a client dials it over AF_UNIX and gets
// the exact NBD handshake + a served READ, and Close removes the socket file so
// a later bind on the same path does not fail. This is the local-attachment
// path a forensic engine uses instead of exposing a TCP port.
func TestNBD_ListenUnix(t *testing.T) {
	data := pattern(1024)
	sock := filepath.Join(t.TempDir(), "nbd.sock")
	l, err := nbd.ListenUnix(sock, &memoryExporter{data: data}, "test")
	if err != nil {
		t.Fatalf("ListenUnix(%s): %v", sock, err)
	}
	done := make(chan error, 1)
	go func() { done <- l.Serve() }()
	t.Cleanup(func() { l.Close() })

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	defer c.Close()

	handshake(t, c, 0x0003)
	sendOption(t, c, optExportName, []byte("test"))
	rsp := readNBD(t, c, 8+2) // NO_ZEROES negotiated
	if size := binary.BigEndian.Uint64(rsp[0:8]); size != 1024 {
		t.Fatalf("export size = %d, want 1024", size)
	}
	if flags := binary.BigEndian.Uint16(rsp[8:10]); flags != wantXmitFlags {
		t.Fatalf("transmission flags = %#x, want %#x", flags, wantXmitFlags)
	}

	sendRequest(t, c, cmdRead, 0x5555, 0, 512)
	errCode, handle, payload := readRequestReply(t, c, 512)
	if errCode != 0 || handle != 0x5555 {
		t.Fatalf("READ err=%d handle=%#x, want 0/0x5555", errCode, handle)
	}
	if !bytes.Equal(payload, data[:512]) {
		t.Fatal("READ over unix socket returned wrong bytes")
	}
	sendRequest(t, c, cmdDisc, 0xdeadbeef, 0, 0)
	// A listener-based Serve() keeps accepting, so it only returns once the
	// listener is closed. Close the client end (the per-connection goroutine
	// returns after DISC) then the listener (the accept loop returns its close
	// error). We only assert that Serve() actually returned.
	_ = c.Close()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-done

	// The socket file must be gone after Close.
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket file %s still exists after Close (stat err = %v)", sock, err)
	}
}
