// This file is derived from the asnlookup project
// (https://github.com/banviktor/asnlookup), licensed under the Apache
// License, Version 2.0. See the LICENSE and NOTICE files.
// It has been modified for use in asname.

package database

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/banviktor/go-mrt"

	"github.com/flyingllama87/asname/pkg/binarytrie"
)

type builder struct {
	prototype  *binarytrie.NaiveTrie
	fillFactor float32
}

// InsertMapping stores an IP prefix - AutonomousSystem mapping.
func (b *builder) InsertMapping(ipNet *net.IPNet, asn uint32) error {
	err := b.prototype.Insert(ipNet, asn)
	if err != nil {
		return err
	}
	return nil
}

const (
	// mrtHeaderLen is the MRT common header: timestamp, type, subtype, length.
	mrtHeaderLen = 12
	// mrtTypeTableDumpV2 is the only MRT record type that carries RIB entries.
	mrtTypeTableDumpV2 = 13
	// maxMRTRecordSize bounds a single record. Anything larger means the stream
	// is not MRT, or framing has been lost, rather than a very large record.
	maxMRTRecordSize = 16 << 20
)

// isRIBSubtype reports whether a TABLE_DUMP_V2 subtype holds RIB entries this
// decoder can read. Subtype 1 is the peer index table, which carries no routes.
// The ADD_PATH subtypes of RFC 8050 (8 to 11) prefix each RIB entry with a path
// identifier the decoder does not expect, so they are skipped rather than
// misread; RIPE RIS dumps contain them alongside the plain subtypes.
func isRIBSubtype(subtype uint16) bool {
	switch subtype {
	case mrt.TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_UNICAST,
		mrt.TABLE_DUMP_V2_SUBTYPE_RIB_IPv4_MULTICAST,
		mrt.TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_UNICAST,
		mrt.TABLE_DUMP_V2_SUBTYPE_RIB_IPv6_MULTICAST:
		return true
	}
	return false
}

// ImportMRT imports records from an MRT stream. It returns the number of records
// that were skipped because this decoder cannot read them.
//
// Framing is done here rather than by the MRT library's reader because that
// reader abandons the stream on the first record type, subtype or path
// attribute it does not recognise, and abandons it mid-record, so everything
// after that point is misread. Collectors legitimately carry records this
// decoder has no use for: RIPE RIS dumps mix ADD_PATH RIB entries in with the
// plain ones and carry path attribute type codes 20, 21 and 255. Reading the
// length from each header and skipping the body keeps the stream aligned, so an
// unreadable record costs only that record.
//
// A header or body that cannot be read in full, a record larger than
// maxMRTRecordSize, and a stream that yields no usable RIB entries at all are
// all treated as failures, so a truncated or corrupt dump is not mistaken for a
// complete one.
func (b *builder) ImportMRT(input io.Reader) (int, error) {
	r := bufio.NewReaderSize(input, 1<<20)
	hdr := make([]byte, mrtHeaderLen)
	body := make([]byte, 0, 4096)

	imported, skipped := 0, 0
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if err == io.EOF {
				break
			}
			return skipped, fmt.Errorf("reading MRT record header: %v", err)
		}
		recordType := binary.BigEndian.Uint16(hdr[4:])
		subtype := binary.BigEndian.Uint16(hdr[6:])
		length := binary.BigEndian.Uint32(hdr[8:])

		if length > maxMRTRecordSize {
			return skipped, fmt.Errorf("MRT record claims %d bytes: the stream is corrupt or not MRT", length)
		}
		if cap(body) < int(length) {
			body = make([]byte, length)
		}
		body = body[:length]
		if _, err := io.ReadFull(r, body); err != nil {
			return skipped, fmt.Errorf("reading MRT record body: %v", err)
		}

		if recordType != mrtTypeTableDumpV2 || !isRIBSubtype(subtype) {
			// The peer index table opens every TABLE_DUMP_V2 dump and carries no
			// routes, so passing over it is not worth reporting.
			if recordType != mrtTypeTableDumpV2 || subtype != mrt.TABLE_DUMP_V2_SUBTYPE_PEER_INDEX_TABLE {
				skipped++
			}
			continue
		}

		// DecodeBytes keeps references into the slice it is given, so each
		// decoded record needs its own copy.
		record := make([]byte, mrtHeaderLen+len(body))
		copy(record, hdr)
		copy(record[mrtHeaderLen:], body)

		rib := new(mrt.TableDumpV2RIB)
		if err := rib.DecodeBytes(record); err != nil {
			skipped++
			continue
		}
		if isNullMask(rib.Prefix.Mask) {
			continue
		}

		prefix, asn, err := mrtRIBToMapping(rib)
		if err != nil {
			continue
		}
		if err := b.InsertMapping(prefix, asn); err != nil {
			return skipped, err
		}
		imported++
	}

	if imported == 0 {
		return skipped, fmt.Errorf("no usable RIB entries in MRT stream (%d records skipped)", skipped)
	}
	return skipped, nil
}

// SetFillFactor sets the fill factor parameter for the optimization phase.
func (b *builder) SetFillFactor(fillFactor float32) {
	b.fillFactor = fillFactor
}

// Build builds the Database instance.
func (b *builder) Build() (Database, error) {
	err := b.prototype.Optimize(b.fillFactor)
	if err != nil {
		return nil, err
	}
	return &database{
		mappings: b.prototype.ToArrayTrie(),
	}, nil
}

// NewBuilder creates a builder.
func NewBuilder() *builder {
	return &builder{
		prototype:  binarytrie.NewNaiveTrie(),
		fillFactor: 0.5,
	}
}

func isNullMask(mask net.IPMask) bool {
	for _, b := range mask {
		if b != 0 {
			return false
		}
	}
	return true
}
