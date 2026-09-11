package database

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// ris-bview-sample.mrt.gz is the opening records of a RIPE RIS rrc04 bview dump
// (bview.20260911.0000.gz). It contains three records carrying BGP path
// attributes this decoder does not know, followed by hundreds it does.
const risSample = "testdata/ris-bview-sample.mrt.gz"

func openSample(t *testing.T) io.Reader {
	t.Helper()
	raw, err := os.ReadFile(risSample)
	require.NoError(t, err)
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	t.Cleanup(func() { gz.Close() })
	return gz
}

func TestImportMRTSkipsUndecodableRecordsAndStaysAligned(t *testing.T) {
	b := NewBuilder()
	skipped, err := b.ImportMRT(openSample(t))
	require.NoError(t, err, "a handful of unknown path attributes must not fail the import")
	require.Equal(t, 3, skipped)

	db, err := b.Build()
	require.NoError(t, err)

	// Records that follow the skipped ones must still have been imported, which
	// only holds if the reader stayed aligned with the record boundaries. The
	// first undecodable record sits at index 440 of 896 in this fixture.
	for _, tc := range []struct {
		ip  string
		asn uint32
	}{
		{"34.136.0.1", 396982}, // Google Cloud, 34.136.0.0/13
		{"57.104.0.1", 16509},  // Amazon, 57.104.0.0/13
		{"75.24.0.1", 7018},    // AT&T, 75.24.0.0/13
		{"121.128.0.1", 4766},  // Korea Telecom, 121.128.0.0/13
	} {
		as, err := db.Lookup(net.ParseIP(tc.ip))
		require.NoError(t, err, tc.ip)
		require.Equal(t, tc.asn, as.Number, tc.ip)
	}
}

// mrtRecord frames an arbitrary body as an MRT record of the given type and subtype.
func mrtRecord(recordType, subtype uint16, body []byte) []byte {
	rec := make([]byte, mrtHeaderLen+len(body))
	binary.BigEndian.PutUint32(rec[0:], 1757560000)
	binary.BigEndian.PutUint16(rec[4:], recordType)
	binary.BigEndian.PutUint16(rec[6:], subtype)
	binary.BigEndian.PutUint32(rec[8:], uint32(len(body)))
	copy(rec[mrtHeaderLen:], body)
	return rec
}

func TestImportMRTSkipsAddPathAndUnknownRecordTypes(t *testing.T) {
	raw, err := os.ReadFile(risSample)
	require.NoError(t, err)
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	sample, err := io.ReadAll(gz)
	require.NoError(t, err)

	// RFC 8050 subtype 10 (RIB_IPV6_UNICAST_ADDPATH) and an unheard-of record
	// type, both carrying bodies that are not valid RIB entries. If their
	// lengths are not honoured, the records that follow are misread.
	var stream []byte
	stream = append(stream, mrtRecord(13, 10, bytes.Repeat([]byte{0xab}, 517))...)
	stream = append(stream, mrtRecord(199, 4, bytes.Repeat([]byte{0x20}, 1033))...)
	stream = append(stream, sample...)

	b := NewBuilder()
	skipped, err := b.ImportMRT(bytes.NewReader(stream))
	require.NoError(t, err)
	require.Equal(t, 5, skipped, "two injected records plus the three undecodable ones")

	db, err := b.Build()
	require.NoError(t, err)
	as, err := db.Lookup(net.ParseIP("57.104.0.1"))
	require.NoError(t, err)
	require.Equal(t, uint32(16509), as.Number, "the dump must still be read after the skipped records")
}

func TestImportMRTRejectsATruncatedStream(t *testing.T) {
	raw, err := os.ReadFile(risSample)
	require.NoError(t, err)
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	full, err := io.ReadAll(gz)
	require.NoError(t, err)

	b := NewBuilder()
	_, err = b.ImportMRT(bytes.NewReader(full[:len(full)-40]))
	require.Error(t, err, "a dump that stops mid-record must not pass as a complete import")
}

func TestImportMRTRejectsGarbage(t *testing.T) {
	garbage := bytes.Repeat([]byte{0xff, 0x00, 0xde, 0xad}, 8192)
	b := NewBuilder()
	_, err := b.ImportMRT(bytes.NewReader(garbage))
	require.Error(t, err, "a stream that is not MRT at all must not pass as an empty import")
}
