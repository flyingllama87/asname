// This file is derived from the asnlookup project
// (https://github.com/banviktor/asnlookup), licensed under the Apache
// License, Version 2.0. See the LICENSE and NOTICE files.
// It has been modified for use in asname.

package database

import (
	"errors"
)

var (
	// ErrNotFound AS not found.
	ErrNotFound = errors.New("AS not found")
)
