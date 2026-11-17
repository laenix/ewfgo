package leveldb

import (
	"bytes"
	"errors"
	"testing"
)

func TestScanFullRecordRoundTrip(t *testing.T) {
	scan, err := ScanLog(EncodeFullRecord([]byte("hello manifest")), DefaultLogLimits())
	if err != nil {
		t.Fatalf("ScanLog: %v", err)
	}
	if len(scan.Records) != 1 {
		t.Fatalf("records = %d", len(scan.Records))
	}
	record := scan.Records[0]
	if !record.CRCOK || record.Offset != 0 || string(record.Payload) != "hello manifest" {
		t.Fatalf("record = %+v", record)
	}
}

func TestScanCorruptRecordKeepsTheBytesFlagged(t *testing.T) {
	bytes := EncodeFullRecord([]byte("payload"))
	bytes[len(bytes)-1] ^= 0xff
	scan, err := ScanLog(bytes, DefaultLogLimits())
	if err != nil {
		t.Fatalf("ScanLog: %v", err)
	}
	if len(scan.Records) != 1 || scan.Records[0].CRCOK {
		t.Fatalf("records = %+v", scan.Records)
	}
	if scan.ChecksumFailures != 1 {
		t.Fatalf("checksum failures = %d", scan.ChecksumFailures)
	}
}

func TestScanFragmentedRecord(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 100)
	stream := append([]byte{}, logFragment(logTypeFirst, payload[0:40])...)
	stream = append(stream, logFragment(logTypeMiddle, payload[40:80])...)
	stream = append(stream, logFragment(logTypeLast, payload[80:100])...)
	scan, err := ScanLog(stream, DefaultLogLimits())
	if err != nil {
		t.Fatalf("ScanLog: %v", err)
	}
	if len(scan.Records) != 1 {
		t.Fatalf("records = %d, warnings = %v", len(scan.Records), scan.Warnings)
	}
	if !bytes.Equal(scan.Records[0].Payload, payload) {
		t.Fatalf("payload = %q", scan.Records[0].Payload)
	}
}

func TestScanMiddleWithoutFirstIsIncomplete(t *testing.T) {
	stream := logFragment(logTypeMiddle, []byte("orphan"))
	scan, err := ScanLog(stream, DefaultLogLimits())
	if err != nil {
		t.Fatalf("ScanLog: %v", err)
	}
	if scan.Incomplete != 1 || len(scan.Records) != 0 {
		t.Fatalf("scan = %+v", scan)
	}
}

func TestScanZeroHeaderSkipsToTheNextBlock(t *testing.T) {
	stream := EncodeFullRecord([]byte("first"))
	if len(stream) > LogBlockBytes {
		t.Fatal("fixture record does not fit one block")
	}
	stream = append(stream, make([]byte, LogBlockBytes-len(stream))...)
	stream = append(stream, EncodeFullRecord([]byte("second"))...)
	scan, err := ScanLog(stream, DefaultLogLimits())
	if err != nil {
		t.Fatalf("ScanLog: %v", err)
	}
	if len(scan.Records) != 2 || string(scan.Records[1].Payload) != "second" {
		t.Fatalf("records = %+v", scan.Records)
	}
}

func TestScanRecordPastItsBlockIsRefused(t *testing.T) {
	stream := make([]byte, LogHeaderBytes)
	stream[4] = byte(40000 & 0xff)
	stream[5] = byte((40000 >> 8) & 0xff)
	stream[6] = logTypeFull
	scan, err := ScanLog(stream, DefaultLogLimits())
	if err != nil {
		t.Fatalf("ScanLog: %v", err)
	}
	if scan.Truncated != 1 || len(scan.Records) != 0 {
		t.Fatalf("scan = %+v", scan)
	}
}

func TestScanLimitsStopWithoutGuessing(t *testing.T) {
	var stream []byte
	for index := 0; index < 3; index++ {
		stream = append(stream, EncodeFullRecord([]byte{byte(index)})...)
	}
	limits := DefaultLogLimits()
	limits.MaxRecords = 2
	scan, err := ScanLog(stream, limits)
	if err != nil {
		t.Fatalf("ScanLog: %v", err)
	}
	if len(scan.Records) != 2 || !scan.StoppedAtLimit {
		t.Fatalf("scan = %+v", scan)
	}

	limits = DefaultLogLimits()
	limits.MaxPayload = 4
	if _, err := ScanLog(EncodeFullRecord([]byte("too large")), limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want a limit error", err)
	}
}

func TestCRCMaskRoundTrips(t *testing.T) {
	for _, value := range []uint32{0, 1, 0x12345678, 0xffffffff} {
		if got := UnmaskCRC(MaskCRC(value)); got != value {
			t.Fatalf("mask round trip %#x -> %#x", value, got)
		}
	}
}
