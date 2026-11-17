package leveldb

import (
	"bytes"
	"testing"
)

func TestDecodeBatchSequencesAndDeletions(t *testing.T) {
	payload := EncodeBatch(100, []BatchEntry{
		{Key: []byte("key1"), Value: []byte("v1")},
		{Key: []byte("key2"), Deleted: true},
	})
	header, err := DecodeBatch(payload, func(sequence uint64, key, value []byte, deleted bool) bool {
		switch sequence {
		case 100:
			if string(key) != "key1" || string(value) != "v1" || deleted {
				t.Fatalf("first entry = %q %q %v", key, value, deleted)
			}
		case 101:
			if string(key) != "key2" || value != nil || !deleted {
				t.Fatalf("second entry = %q %q %v", key, value, deleted)
			}
		default:
			t.Fatalf("unexpected sequence %d", sequence)
		}
		return true
	})
	if err != nil {
		t.Fatalf("DecodeBatch: %v", err)
	}
	if header.Sequence != 100 || header.Count != 2 {
		t.Fatalf("header = %+v", header)
	}
}

func TestWalSummarizesValuesAndDeletions(t *testing.T) {
	var stream []byte
	stream = append(stream, EncodeFullRecord(EncodeBatch(10, []BatchEntry{
		{Key: []byte("a"), Value: []byte("one")},
		{Key: []byte("b"), Value: []byte("two")},
	}))...)
	stream = append(stream, EncodeFullRecord(EncodeBatch(12, []BatchEntry{
		{Key: []byte("b"), Deleted: true},
	}))...)
	log, err := OpenLog(memorySource(stream))
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if log.Records != 2 || log.Batches != 2 || log.Entries != 3 || log.Deletions != 1 {
		t.Fatalf("log = %+v", log)
	}
	if log.FirstSequence == nil || *log.FirstSequence != 10 ||
		log.LastSequence == nil || *log.LastSequence != 12 {
		t.Fatalf("sequences = %v..%v", log.FirstSequence, log.LastSequence)
	}
	if log.FirstKey == nil || *log.FirstKey != "a" ||
		log.LastKey == nil || *log.LastKey != "b" {
		t.Fatalf("keys = %v..%v", log.FirstKey, log.LastKey)
	}
	if log.KeyBytes != 3 || log.ValueBytes != 6 {
		t.Fatalf("bytes = %d/%d", log.KeyBytes, log.ValueBytes)
	}
}

func TestWalFragmentedBatchIsStitched(t *testing.T) {
	payload := EncodeBatch(50, []BatchEntry{
		{Key: []byte("first"), Value: []byte("value-one")},
		{Key: []byte("second"), Value: []byte("value-two")},
	})
	var stream []byte
	cut1, cut2 := 5, 11
	stream = append(stream, logFragment(logTypeFirst, payload[:cut1])...)
	stream = append(stream, logFragment(logTypeMiddle, payload[cut1:cut2])...)
	stream = append(stream, logFragment(logTypeLast, payload[cut2:])...)
	log, err := OpenLog(memorySource(stream))
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if log.Records != 1 || log.Batches != 1 || log.Entries != 2 || log.Deletions != 0 {
		t.Fatalf("log = %+v, warnings = %v", log, log.Warnings)
	}
	if log.FirstSequence == nil || *log.FirstSequence != 50 ||
		log.LastSequence == nil || *log.LastSequence != 51 {
		t.Fatalf("sequences = %v..%v", log.FirstSequence, log.LastSequence)
	}
}

func TestWalCRCFailureSkipsTheBatch(t *testing.T) {
	record := EncodeFullRecord(EncodeBatch(1, []BatchEntry{{Key: []byte("k"), Value: []byte("v")}}))
	record[len(record)-1] ^= 0xff
	log, err := OpenLog(memorySource(record))
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if log.ChecksumFailures != 1 || log.Batches != 0 || log.Entries != 0 {
		t.Fatalf("log = %+v", log)
	}
	if len(log.Warnings) == 0 {
		t.Fatal("a checksum failure produced no warning")
	}
}

func TestWalTruncatedBatchContributesNoEntries(t *testing.T) {
	payload := EncodeBatch(1, []BatchEntry{{Key: []byte("key"), Value: []byte("value")}})
	payload = payload[:len(payload)-2]
	log, err := OpenLog(memorySource(EncodeFullRecord(payload)))
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if log.DecodeFailures != 1 || log.Batches != 0 || log.Entries != 0 {
		t.Fatalf("log = %+v", log)
	}
}

func TestWalRejectsAnUnknownValueType(t *testing.T) {
	payload := EncodeBatch(1, []BatchEntry{{Key: []byte("k"), Value: []byte("v")}})
	payload[12] = 2 // neither a deletion nor a value
	if _, err := DecodeBatch(payload, func(uint64, []byte, []byte, bool) bool { return true }); err == nil {
		t.Fatal("a batch with value type 2 decoded")
	}
	if _, err := DecodeBatch(make([]byte, 4), func(uint64, []byte, []byte, bool) bool { return true }); err == nil {
		t.Fatal("a four-byte batch decoded")
	}
}

func TestWalEmptyValueIsNotADeletion(t *testing.T) {
	log, err := OpenLog(memorySource(EncodeFullRecord(EncodeBatch(1, []BatchEntry{
		{Key: []byte("empty"), Value: []byte{}},
		{Key: []byte("gone"), Deleted: true},
	}))))
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if log.Entries != 2 || log.Deletions != 1 || log.ValueBytes != 0 {
		t.Fatalf("log = %+v", log)
	}
}

func TestWalLimitsStopTheScan(t *testing.T) {
	stream := append([]byte{}, EncodeFullRecord(EncodeBatch(1, []BatchEntry{{Key: []byte("a"), Value: []byte("v")}}))...)
	stream = append(stream, EncodeFullRecord(EncodeBatch(2, []BatchEntry{{Key: []byte("b"), Value: []byte("v")}}))...)
	limits := DefaultLogLimits()
	limits.MaxRecords = 1
	log, err := OpenLogWithLimits(memorySource(stream), limits)
	if err != nil {
		t.Fatalf("OpenLogWithLimits: %v", err)
	}
	if log.Records != 1 || log.Batches != 1 || !log.StoppedAtLimit {
		t.Fatalf("log = %+v", log)
	}
	if log.Entries != 1 || log.FirstKey == nil || *log.FirstKey != "a" {
		t.Fatalf("entries = %+v", log)
	}
	if bytes.Contains([]byte(*log.FirstKey), []byte("b")) {
		t.Fatal("the stopped scan invented an entry")
	}
}
