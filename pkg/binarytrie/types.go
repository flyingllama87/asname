// This file is derived from the asnlookup project
// (https://github.com/banviktor/asnlookup), licensed under the Apache
// License, Version 2.0. See the LICENSE and NOTICE files.
// It is used unmodified.

package binarytrie

import (
	"net"
)

type Trie interface {
	// Insert inserts an IP network - value mapping into the trie.
	Insert(*net.IPNet, uint32) error
	// Lookup returns a value for the given IP address.
	Lookup(ip net.IP) (uint32, error)
}
