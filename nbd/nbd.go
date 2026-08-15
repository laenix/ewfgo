// Package nbd implements a pure-Go Network Block Device (NBD) server using the
// NBD newstyle protocol. It exposes a byte-addressable block source over a TCP
// connection so an external forensic tool (Linux nbd-client + the kernel nbd
// driver, qemu, or a GUI suite) can attach an EWF image as a read-only block
// device.
//
// The implementation is pure Go and cross-platform: it uses only the standard
// library, never CGO, and never spawns external processes. There is no syscall
// use — signal handling for a server lifecycle belongs to the CLI (os/signal).
//
// Wire values (all integers big-endian):
//
//	handshake    NBDMAGIC(0x4e42444d41474943) IHAVEOPT(0x49484156454f5054) flags(0x0003)
//	option       IHAVEOPT(0x49484156454f5054) code(4) length(4) payload
//	option reply NBD_REP_MAGIC(0x0003e889045565a9) code(4) reply(4) length(4) payload
//	request      NBD_REQUEST_MAGIC(0x25609513) flags(2) type(2) handle(8) offset(8) length(4)
//	reply        NBD_REPLY_MAGIC(0x67446698) error(4) handle(8) payload
//
// The export is read-only: the write-family commands (WRITE, TRIM,
// WRITE_ZEROES) are answered EPERM, FLUSH succeeds, and anything not advertised
// (CACHE, BLOCK_STATUS) is EINVAL. A READ whose range falls outside the export
// is answered EINVAL — wrong bytes are never served. A malformed client (short
// reads, bad magic) closes the connection via an error; the server never
// panics.
package nbd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
)

// Wire constants — NBD newstyle protocol.
const (
	nbdMagic    uint64 = 0x4e42444d41474943 // "NBDMAGIC"
	nbdOptMagic uint64 = 0x49484156454f5054 // "IHAVEOPT"
	nbdRepMagic uint64 = 0x0003e889045565a9 // "NBD_REP_MAGIC"

	nbdReqMagic uint32 = 0x25609513 // "NBD_REQUEST_MAGIC"
	nbdRplMagic uint32 = 0x67446698 // "NBD_REPLY_MAGIC"

	// Handshake flags (2 bytes) sent by the server in the greeting.
	nbdFlagFixedNewstyle uint16 = 0x0001
	nbdFlagNoZeroes      uint16 = 0x0002
	nbdHandshakeFlags           = nbdFlagFixedNewstyle | nbdFlagNoZeroes // 0x0003

	// Client flags (4 bytes).
	nbdClientFixedNewstyle uint32 = 0x00000001
	nbdClientNoZeroes      uint32 = 0x00000002

	// Transmission flags (2 bytes). This is a read-only forensic export, so the
	// write-related flags (SEND_WRITE_ZEROES, SEND_TRIM, ...) are NOT
	// advertised.
	nbdFlagHasFlags      uint16 = 0x0001
	nbdFlagReadOnly      uint16 = 0x0002
	nbdFlagSendFlush     uint16 = 0x0004
	nbdTransmissionFlags        = nbdFlagHasFlags | nbdFlagReadOnly | nbdFlagSendFlush // 0x0007

	// Option codes.
	nbdOptExportName      uint32 = 1
	nbdOptAbort           uint32 = 2
	nbdOptList            uint32 = 3
	nbdOptInfo            uint32 = 6
	nbdOptGo              uint32 = 7
	nbdOptStructuredReply uint32 = 8

	// Option reply types.
	nbdRepAck      uint32 = 1
	nbdRepServer   uint32 = 2
	nbdRepInfo     uint32 = 3
	nbdRepErrUnsup uint32 = 0x80000001 // 2^31 + 1

	// NBD_INFO_* info types carried inside NBD_REP_INFO payloads. Per the NBD
	// protocol spec, NBD_INFO_EXPORT is 0 (export size + transmission flags);
	// 1 is NBD_INFO_NAME, 2 is NBD_INFO_DESCRIPTION, 3 is NBD_INFO_BLOCK_SIZE.
	nbdInfoExport uint16 = 0

	// Command types.
	nbdCmdRead        uint16 = 0
	nbdCmdWrite       uint16 = 1
	nbdCmdDisc        uint16 = 2
	nbdCmdFlush       uint16 = 3
	nbdCmdTrim        uint16 = 4
	nbdCmdCache       uint16 = 5
	nbdCmdWriteZeroes uint16 = 6
	nbdCmdBlockStatus uint16 = 7

	// Linux errnos echoed in the 4-byte NBD reply error field.
	errnoEPERM   uint32 = 1
	errnoEIO     uint32 = 5
	errnoEINVAL  uint32 = 22
	errnoENOTSUP uint32 = 95
)

const (
	// maxOptionLen caps the bytes the server will read for a single option
	// payload. Real newstyle option payloads are short (export names are at
	// most a few hundred bytes); the cap guards against a malicious 4 GiB
	// length field causing a huge allocation. A larger payload is a protocol
	// violation and closes the connection.
	maxOptionLen = 4096

	// maxReadLen caps a single READ request. It matches the Linux kernel NBD
	// client's request size and guards allocation from a malicious length.
	maxReadLen = 32 << 20 // 32 MiB
)

// Exporter is the byte-addressable block source served over NBD. Size returns
// the export size in bytes; ReadAt implements io.ReaderAt semantics — it reads
// len(p) bytes at off, or returns a shorter prefix together with a non-nil
// error (io.EOF at the end of the export). Implementations must never fabricate
// bytes past the export size.
type Exporter interface {
	Size() uint64
	ReadAt(p []byte, off int64) (int, error)
}

// Server serves one NBD connection against an Exporter using the newstyle
// protocol. Construct with NewServer and drive with Serve. A Server is
// single-use.
type Server struct {
	conn net.Conn
	exp  Exporter
	name string

	noZeroes bool // client negotiated NBD_FLAG_C_NO_ZEROES
}

// NewServer returns a Server that will serve the connection conn against the
// block source exp, advertising the export name.
func NewServer(conn net.Conn, exp Exporter, name string) *Server {
	return &Server{conn: conn, exp: exp, name: name}
}

// errNegotiationDone signals that NBD_OPT_ABORT ended the session cleanly.
var errNegotiationDone = errors.New("nbd: negotiation ended by NBD_OPT_ABORT")

// Serve runs the full newstyle handshake, option negotiation, and transmission
// loop, returning when the client disconnects or on a fatal protocol error. It
// closes the connection when it returns. Serve never panics on a malformed
// client: short reads and bad magics are returned as errors, which close the
// connection.
func (s *Server) Serve() error {
	defer s.conn.Close()
	if err := s.handshake(); err != nil {
		return err
	}
	for {
		enter, err := s.handleOption()
		if err == errNegotiationDone {
			return nil
		}
		if err != nil {
			return err
		}
		if enter {
			return s.transmission()
		}
	}
}

// handshake performs the server side of the newstyle handshake: it writes the
// greeting (NBDMAGIC + IHAVEOPT + handshake flags 0x0003) and reads the client
// flags. Only newstyle clients are accepted: a client that does not set
// NBD_FLAG_C_FIXED_NEWSTYLE (including an oldstyle client sending 0) gets the
// connection closed with an error.
func (s *Server) handshake() error {
	var g [18]byte
	binary.BigEndian.PutUint64(g[0:8], nbdMagic)
	binary.BigEndian.PutUint64(g[8:16], nbdOptMagic)
	binary.BigEndian.PutUint16(g[16:18], nbdHandshakeFlags)
	if _, err := s.conn.Write(g[:]); err != nil {
		return fmt.Errorf("nbd: write handshake greeting: %w", err)
	}

	var cf [4]byte
	if _, err := io.ReadFull(s.conn, cf[:]); err != nil {
		return fmt.Errorf("nbd: read client flags: %w", err)
	}
	flags := binary.BigEndian.Uint32(cf[:])
	if flags&nbdClientFixedNewstyle == 0 {
		return fmt.Errorf("nbd: client flags %#x request non-newstyle negotiation", flags)
	}
	s.noZeroes = flags&nbdClientNoZeroes != 0
	return nil
}

// handleOption reads one option (IHAVEOPT magic + code + length + payload) and
// answers it. It returns enter == true when the server must enter the
// transmission phase (NBD_OPT_EXPORT_NAME / NBD_OPT_GO) and errNegotiationDone
// for a clean NBD_OPT_ABORT close.
func (s *Server) handleOption() (enter bool, err error) {
	var hdr [16]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return false, fmt.Errorf("nbd: read option header: %w", err)
	}
	if magic := binary.BigEndian.Uint64(hdr[0:8]); magic != nbdOptMagic {
		return false, fmt.Errorf("nbd: bad option magic %#x", magic)
	}
	code := binary.BigEndian.Uint32(hdr[8:12])
	length := binary.BigEndian.Uint32(hdr[12:16])
	if length > maxOptionLen {
		return false, fmt.Errorf("nbd: option payload length %d exceeds %d", length, maxOptionLen)
	}
	// Read the full payload even when the option is unused.
	payload := make([]byte, length)
	if _, err := io.ReadFull(s.conn, payload); err != nil {
		return false, fmt.Errorf("nbd: read option payload: %w", err)
	}

	switch code {
	case nbdOptExportName:
		// No option-reply header for EXPORT_NAME: 8-byte size + 2-byte
		// transmission flags, then 124 zero bytes unless NO_ZEROES was
		// negotiated.
		size := s.exp.Size()
		var rsp [10]byte
		binary.BigEndian.PutUint64(rsp[0:8], size)
		binary.BigEndian.PutUint16(rsp[8:10], nbdTransmissionFlags)
		if _, err := s.conn.Write(rsp[:]); err != nil {
			return false, err
		}
		if !s.noZeroes {
			if _, err := s.conn.Write(make([]byte, 124)); err != nil {
				return false, err
			}
		}
		return true, nil

	case nbdOptAbort:
		if err := s.writeOptionReply(nbdOptAbort, nbdRepAck, nil); err != nil {
			return false, err
		}
		return false, errNegotiationDone

	case nbdOptList:
		namePayload := make([]byte, 4+len(s.name))
		binary.BigEndian.PutUint32(namePayload[0:4], uint32(len(s.name)))
		copy(namePayload[4:], s.name)
		if err := s.writeOptionReply(nbdOptList, nbdRepServer, namePayload); err != nil {
			return false, err
		}
		if err := s.writeOptionReply(nbdOptList, nbdRepAck, nil); err != nil {
			return false, err
		}
		return false, nil

	case nbdOptInfo, nbdOptGo:
		if err := s.writeOptionReply(code, nbdRepInfo, s.infoPayload()); err != nil {
			return false, err
		}
		if err := s.writeOptionReply(code, nbdRepAck, nil); err != nil {
			return false, err
		}
		return code == nbdOptGo, nil

	case nbdOptStructuredReply:
		if err := s.writeOptionReply(nbdOptStructuredReply, nbdRepErrUnsup, nil); err != nil {
			return false, err
		}
		return false, nil

	default:
		if err := s.writeOptionReply(code, nbdRepErrUnsup, nil); err != nil {
			return false, err
		}
		return false, nil
	}
}

// infoPayload returns the NBD_REP_INFO payload for NBD_INFO_EXPORT: 2-byte info
// type + 8-byte size + 2-byte transmission flags.
func (s *Server) infoPayload() []byte {
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p[0:2], nbdInfoExport)
	binary.BigEndian.PutUint64(p[2:10], s.exp.Size())
	binary.BigEndian.PutUint16(p[10:12], nbdTransmissionFlags)
	return p
}

// writeOptionReply writes an option reply header (NBD_REP_MAGIC + echoed option
// code + reply type + payload length) followed by the payload.
func (s *Server) writeOptionReply(code, reply uint32, payload []byte) error {
	var hdr [20]byte
	binary.BigEndian.PutUint64(hdr[0:8], nbdRepMagic)
	binary.BigEndian.PutUint32(hdr[8:12], code)
	binary.BigEndian.PutUint32(hdr[12:16], reply)
	binary.BigEndian.PutUint32(hdr[16:20], uint32(len(payload)))
	if _, err := s.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// transmission runs the request/reply loop. Read-only enforcement happens here:
// write-family commands answer EPERM, and a READ outside the export answers
// EINVAL — never fabricated bytes. It returns nil on NBD_CMD_DISC or a clean
// client EOF.
func (s *Server) transmission() error {
	for {
		var req [28]byte
		if _, err := io.ReadFull(s.conn, req[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("nbd: read request: %w", err)
		}
		if magic := binary.BigEndian.Uint32(req[0:4]); magic != nbdReqMagic {
			return fmt.Errorf("nbd: bad request magic %#x", magic)
		}
		typ := binary.BigEndian.Uint16(req[6:8])
		handle := req[8:16]
		offset := binary.BigEndian.Uint64(req[16:24])
		length := binary.BigEndian.Uint32(req[24:28])

		switch typ {
		case nbdCmdRead:
			size := s.exp.Size()
			// Bounds check without overflow: offset <= size and the range
			// length <= size-offset. A READ past the end is EINVAL.
			if offset > size || uint64(length) > size-offset {
				if err := s.writeRequestReply(handle, errnoEINVAL, nil); err != nil {
					return err
				}
				continue
			}
			if length == 0 {
				if err := s.writeRequestReply(handle, 0, nil); err != nil {
					return err
				}
				continue
			}
			if length > maxReadLen {
				if err := s.writeRequestReply(handle, errnoEINVAL, nil); err != nil {
					return err
				}
				continue
			}
			if offset > math.MaxInt64 {
				// Cannot be expressed as an int64; out of the addressable
				// range of any real export.
				if err := s.writeRequestReply(handle, errnoEINVAL, nil); err != nil {
					return err
				}
				continue
			}
			data := make([]byte, length)
			n, err := s.exp.ReadAt(data, int64(offset))
			// io.ReaderAt: a full read must carry a nil error. Anything short
			// of the requested length is served as EIO, never partial data.
			if n != int(length) || err != nil {
				if err := s.writeRequestReply(handle, errnoEIO, nil); err != nil {
					return err
				}
				continue
			}
			if err := s.writeRequestReply(handle, 0, data); err != nil {
				return err
			}

		case nbdCmdWrite, nbdCmdTrim, nbdCmdWriteZeroes:
			// Read-only forensic export: the write-family is rejected.
			if err := s.writeRequestReply(handle, errnoEPERM, nil); err != nil {
				return err
			}

		case nbdCmdFlush:
			if err := s.writeRequestReply(handle, 0, nil); err != nil {
				return err
			}

		case nbdCmdDisc:
			return nil

		case nbdCmdCache, nbdCmdBlockStatus:
			// Not advertised on this export.
			if err := s.writeRequestReply(handle, errnoEINVAL, nil); err != nil {
				return err
			}

		default:
			if err := s.writeRequestReply(handle, errnoEINVAL, nil); err != nil {
				return err
			}
		}
	}
}

// writeRequestReply writes a transmission-phase simple reply: NBD_REPLY_MAGIC +
// 4-byte error + 8-byte echoed handle + payload.
func (s *Server) writeRequestReply(handle []byte, errCode uint32, payload []byte) error {
	var hdr [16]byte
	binary.BigEndian.PutUint32(hdr[0:4], nbdRplMagic)
	binary.BigEndian.PutUint32(hdr[4:8], errCode)
	copy(hdr[8:16], handle)
	if _, err := s.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// Listener accepts NBD connections on a network listener and serves each one in
// its own goroutine. Create one with Listen (TCP) or ListenUnix (Unix socket).
type Listener struct {
	ln       net.Listener
	exp      Exporter
	name     string
	unixPath string // set by ListenUnix; the socket file is removed on Close
}

// Listen binds a Listener to addr. Use Serve to accept connections, Close to
// stop accepting, and Addr for the bound address.
func Listen(addr string, exp Exporter, name string) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("nbd: listen on %s: %w", addr, err)
	}
	return &Listener{ln: ln, exp: exp, name: name}, nil
}

// ListenUnix binds a Listener to a Unix domain socket at path. It lets a local
// forensic engine attach the export over the filesystem namespace (no TCP port
// exposed). The socket file is removed when the listener is closed.
func ListenUnix(path string, exp Exporter, name string) (*Listener, error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("nbd: listen on unix socket %s: %w", path, err)
	}
	return &Listener{ln: ln, exp: exp, name: name, unixPath: path}, nil
}

// Addr returns the bound network address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close stops the listener from accepting new connections. In-flight
// connections are not interrupted. A Unix-socket listener also removes its
// socket file, so a later ListenUnix on the same path does not fail with
// "address already in use".
func (l *Listener) Close() error {
	err := l.ln.Close()
	if l.unixPath != "" {
		if rmErr := os.Remove(l.unixPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) && err == nil {
			err = rmErr
		}
	}
	return err
}

// Serve accepts connections until the listener is closed (returning the accept
// error) or Accept fails. Each accepted connection runs NewServer(...).Serve in
// its own goroutine; a per-connection error does not stop the accept loop.
func (l *Listener) Serve() error {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = NewServer(c, l.exp, l.name).Serve()
		}(conn)
	}
}

// ListenAndServe binds a Listener on addr and serves connections until the
// listener fails or is closed. For the command line, the default address is
// 127.0.0.1:10809 (the IANA NBD port). Tests drive NewServer directly over
// net.Pipe and never bind a port.
func ListenAndServe(addr string, exp Exporter, name string) error {
	l, err := Listen(addr, exp, name)
	if err != nil {
		return err
	}
	defer l.Close()
	return l.Serve()
}
