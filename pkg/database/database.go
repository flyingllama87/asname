// This file is derived from the asnlookup project
// (https://github.com/banviktor/asnlookup), licensed under the Apache
// License, Version 2.0. See the LICENSE and NOTICE files.
// It has been modified for use in asname.

package database

import (
	"encoding"
	"fmt"
	"io"
	"net"

	"github.com/flyingllama87/asname/pkg/binarytrie"
)

// AutonomousSystem represents an Autonomous System on the Internet.
type AutonomousSystem struct {
	// Number (aka ASN) is the unique identifier for an Autonomous System.
	Number uint32
}

// Database stores mappings between IP addresses and Autonomous Systems.
type Database interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	// Lookup returns the AutonomousSystem for a given net.IP.
	Lookup(net.IP) (AutonomousSystem, error)
}

type database struct {
	mappings *binarytrie.ArrayTrie
}

// Lookup implements Database.
func (d *database) Lookup(ip net.IP) (AutonomousSystem, error) {
	asn, err := d.mappings.Lookup(ip)
	if err == binarytrie.ErrValueNotFound {
		return AutonomousSystem{}, ErrNotFound
	} else if err != nil {
		return AutonomousSystem{}, fmt.Errorf("lookup failed: %v", err)
	}

	return AutonomousSystem{
		Number: asn,
	}, nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (d *database) MarshalBinary() ([]byte, error) {
	return d.mappings.MarshalBinary()
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (d *database) UnmarshalBinary(data []byte) error {
	return d.mappings.UnmarshalBinary(data)
}

func NewFromDump(r io.Reader) (Database, error) {
	d := &database{
		mappings: binarytrie.NewArrayTrie(),
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %v", err)
	}

	if err = d.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("failed to restore dump: %v", err)
	}
	return d, nil
}

// Walk calls fn, in ascending address order, for every maximal range of
// addresses db maps to one value, stopping early when fn returns false. start
// and end are inclusive; IPv4 ranges come IPv4-mapped (::ffff:a.b.c.d). It
// works on databases made by this package and reports an error for any other
// implementation of Database.
func Walk(db Database, fn func(start, end [16]byte, value uint32) bool) error {
	d, ok := db.(*database)
	if !ok {
		return fmt.Errorf("walk: unsupported database type %T", db)
	}
	d.mappings.Walk(fn)
	return nil
}
