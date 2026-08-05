// This file is derived from the asnlookup project
// (https://github.com/banviktor/asnlookup), licensed under the Apache
// License, Version 2.0. See the LICENSE and NOTICE files.
// It has been modified for use in asname.

package binarytrie_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/flyingllama87/asname/pkg/binarytrie"
)

func TestEmptyMarshaledArrayTrieLookup(t *testing.T) {
	trie, testCases := newEmptyNaiveTrie()
	assert.NoError(t, trie.Optimize(0.5), "Optimize should not error")
	arrayTrie := trie.ToArrayTrie()

	buf, err := arrayTrie.MarshalBinary()
	assert.NoError(t, err, "MarshalBinary should not error")

	newTrie := &ArrayTrie{}
	err = newTrie.UnmarshalBinary(buf)
	assert.NoError(t, err, "UnmarshalBinary should not error")

	testLookup(t, newTrie, testCases)
}

func TestTrivialMarshaledArrayTrieLookup(t *testing.T) {
	trie, testCases := newTrivialNaiveTrie()
	assert.NoError(t, trie.Optimize(0.5), "Optimize should not error")
	arrayTrie := trie.ToArrayTrie()

	buf, err := arrayTrie.MarshalBinary()
	assert.NoError(t, err, "MarshalBinary should not error")

	newTrie := &ArrayTrie{}
	err = newTrie.UnmarshalBinary(buf)
	assert.NoError(t, err, "UnmarshalBinary should not error")

	testLookup(t, newTrie, testCases)
}

func TestPopulatedMarshaledArrayTrieLookup(t *testing.T) {
	trie, testCases := newPopulatedNaiveTrie()
	assert.NoError(t, trie.Optimize(0.5), "Optimize should not error")
	arrayTrie := trie.ToArrayTrie()

	buf, err := arrayTrie.MarshalBinary()
	assert.NoError(t, err, "MarshalBinary should not error")

	newTrie := &ArrayTrie{}
	err = newTrie.UnmarshalBinary(buf)
	assert.NoError(t, err, "UnmarshalBinary should not error")

	testLookup(t, newTrie, testCases)
}
