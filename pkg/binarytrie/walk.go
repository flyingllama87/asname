package binarytrie

import "bytes"

// Walk calls fn, in ascending address order, for every maximal range of
// addresses that Lookup maps to the same value. start and end are inclusive
// 16-byte addresses, with IPv4 held IPv4-mapped (::ffff:a.b.c.d) as Insert
// stores it. Addresses without a value are skipped. The walk stops early when
// fn returns false.
func (t *ArrayTrie) Walk(fn func(start, end [16]byte, value uint32) bool) {
	if len(t.nodes) == 0 {
		return
	}
	w := walker{t: t, fn: fn}
	w.node(0, [16]byte{}, 0, 0)
	if !w.stopped && w.open {
		w.fn(w.start, w.end, w.value)
	}
}

// walker merges the ranges the trie yields in order into maximal runs.
type walker struct {
	t       *ArrayTrie
	fn      func(start, end [16]byte, value uint32) bool
	open    bool
	start   [16]byte
	end     [16]byte
	value   uint32
	stopped bool
}

func (w *walker) emit(start, end [16]byte, value uint32) {
	if w.stopped {
		return
	}
	if w.open && value == w.value && next(w.end) == start {
		w.end = end
		return
	}
	if w.open && !w.fn(w.start, w.end, w.value) {
		w.stopped = true
		return
	}
	w.open = value != 0
	w.start, w.end, w.value = start, end, value
}

// node walks the subtree at index covering prefix/depth, where value is the
// value Lookup has seen on the way down. It mirrors Lookup: an address whose
// skipped bits do not match a child's stops there and keeps value.
func (w *walker) node(index int, prefix [16]byte, depth int, value uint32) {
	n := w.t.nodes[index]
	if n.value != 0 {
		value = n.value
	}
	first, last := prefix, lastAddr(prefix, depth)
	if n.isLeaf() {
		w.emit(first, last, value)
		return
	}

	type child struct {
		index  int
		prefix [16]byte
	}
	skip, bf := int(n.skipValue), int(n.branchingFactor)
	children := make([]child, 0, 1<<bf)
	for c := 0; c < 1<<bf; c++ {
		ci := index + int(n.childrenOffset) + c
		p := prefix
		if skip > 0 {
			bits, ok := w.t.skippedBits[ci]
			if !ok {
				continue
			}
			setBits(&p, depth, skip, bits)
		}
		setBits(&p, depth+skip, bf, uint32(c))
		children = append(children, child{ci, p})
	}

	cursor, done := first, false
	for _, c := range children {
		if bytes.Compare(c.prefix[:], cursor[:]) > 0 {
			w.emit(cursor, prev(c.prefix), value)
		}
		w.node(c.index, c.prefix, depth+skip+bf, value)
		end := lastAddr(c.prefix, depth+skip+bf)
		if end == last {
			done = true
			break
		}
		cursor = next(end)
	}
	if !done {
		w.emit(cursor, last, value)
	}
}

// setBits writes the low length bits of v into ip from bit position onwards,
// counting from the most significant bit, as extractBits reads them.
func setBits(ip *[16]byte, position, length int, v uint32) {
	for i := 0; i < length; i++ {
		bit := position + i
		mask := byte(0x80) >> (bit % 8)
		if v&(1<<(length-1-i)) != 0 {
			ip[bit/8] |= mask
		} else {
			ip[bit/8] &^= mask
		}
	}
}

// lastAddr returns the last address of prefix/depth.
func lastAddr(prefix [16]byte, depth int) [16]byte {
	for bit := depth; bit < 128; bit++ {
		prefix[bit/8] |= byte(0x80) >> (bit % 8)
	}
	return prefix
}

func next(a [16]byte) [16]byte {
	for i := 15; i >= 0; i-- {
		a[i]++
		if a[i] != 0 {
			break
		}
	}
	return a
}

func prev(a [16]byte) [16]byte {
	for i := 15; i >= 0; i-- {
		a[i]--
		if a[i] != 0xff {
			break
		}
	}
	return a
}
