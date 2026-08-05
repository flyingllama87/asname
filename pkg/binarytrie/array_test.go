// This file is derived from the asnlookup project
// (https://github.com/banviktor/asnlookup), licensed under the Apache
// License, Version 2.0. See the LICENSE and NOTICE files.
// It has been modified for use in asname.

package binarytrie_test

import (
	"testing"
)

func TestEmptyArrayTrieLookup(t *testing.T) {
	trie, testCases := newEmptyNaiveTrie()
	testLookup(t, trie.ToArrayTrie(), testCases)
}

func TestTrivialArrayTrieLookup(t *testing.T) {
	trie, testCases := newTrivialNaiveTrie()
	testLookup(t, trie.ToArrayTrie(), testCases)
}

func TestPopulatedArrayTrieLookup(t *testing.T) {
	trie, testCases := newPopulatedNaiveTrie()
	testLookup(t, trie.ToArrayTrie(), testCases)
}
