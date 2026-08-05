// This file is derived from the asnlookup project
// (https://github.com/banviktor/asnlookup), licensed under the Apache
// License, Version 2.0. See the LICENSE and NOTICE files.
// It is used unmodified.

package binarytrie

import (
	"errors"
)

var (
	// ErrInvalidIPAddress IP address is invalid.
	ErrInvalidIPAddress = errors.New("invalid IP address")
	// ErrTrieImmutable Trie is immutable.
	ErrTrieImmutable = errors.New("trie is immutable")
	// ErrValueNotFound value was not found.
	ErrValueNotFound = errors.New("value not found")
	// ErrInvalidFormat invalid marshaled input.
	ErrInvalidFormat = errors.New("invalid format")
)
