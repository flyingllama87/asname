package binarytrie_test

import (
	"bytes"
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flyingllama87/asname/pkg/binarytrie"
)

type walkRange struct {
	start, end [16]byte
	value      uint32
}

// TestArrayTrieWalkMatchesLookup builds random tries, walks them, and checks
// every range against Lookup: its ends and random addresses inside it carry
// its value, the addresses just outside it do not, and addresses between
// ranges have no value.
func TestArrayTrieWalkMatchesLookup(t *testing.T) {
	for _, fill := range []float32{0.25, 0.5, 1} {
		for seed := int64(1); seed <= 20; seed++ {
			rng := rand.New(rand.NewSource(seed))
			trie := binarytrie.NewNaiveTrie()
			for i := 0; i < 200; i++ {
				var ipNet *net.IPNet
				if rng.Intn(2) == 0 {
					ip := net.IPv4(byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)))
					ipNet = &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(8+rng.Intn(25), 32)}
				} else {
					ip := make(net.IP, 16)
					ip[0] = 0x20
					rng.Read(ip[1:8])
					ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(16+rng.Intn(49), 128)}
				}
				ipNet.IP = ipNet.IP.Mask(ipNet.Mask)
				require.NoError(t, trie.Insert(ipNet, uint32(1+rng.Intn(4))))
			}
			require.NoError(t, trie.Optimize(fill))
			at := trie.ToArrayTrie()

			var ranges []walkRange
			at.Walk(func(start, end [16]byte, value uint32) bool {
				ranges = append(ranges, walkRange{start, end, value})
				return true
			})
			require.NotEmpty(t, ranges)

			lookup := func(a [16]byte) uint32 {
				v, _ := at.Lookup(net.IP(a[:]))
				return v
			}
			for i, r := range ranges {
				require.LessOrEqual(t, bytes.Compare(r.start[:], r.end[:]), 0)
				require.NotZero(t, r.value)
				require.Equal(t, r.value, lookup(r.start), "fill %v seed %d range %d start", fill, seed, i)
				require.Equal(t, r.value, lookup(r.end), "fill %v seed %d range %d end", fill, seed, i)
				if i > 0 {
					require.Less(t, bytes.Compare(ranges[i-1].end[:], r.start[:]), 0, "ranges ascend without overlap")
				}
				before, after := r.start, r.end
				decr(&before)
				incr(&after)
				if r.start != [16]byte{} {
					require.NotEqual(t, r.value, lookup(before), "range is maximal at its start")
				}
				if r.end != lastAll {
					require.NotEqual(t, r.value, lookup(after), "range is maximal at its end")
				}
				// Where the next range does not follow directly, the gap has no value.
				if r.end != lastAll && (i+1 == len(ranges) || ranges[i+1].start != after) {
					require.Zero(t, lookup(after))
				}
			}
		}
	}
}

func TestArrayTrieWalkStopsEarly(t *testing.T) {
	trie := binarytrie.NewNaiveTrie()
	for _, cidr := range []string{"1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8"} {
		_, n, _ := net.ParseCIDR(cidr)
		require.NoError(t, trie.Insert(n, 7))
	}
	require.NoError(t, trie.Optimize(0.5))
	calls := 0
	trie.ToArrayTrie().Walk(func(start, end [16]byte, value uint32) bool {
		calls++
		return false
	})
	require.Equal(t, 1, calls)
}

var lastAll = [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func incr(a *[16]byte) {
	for i := 15; i >= 0; i-- {
		a[i]++
		if a[i] != 0 {
			return
		}
	}
}

func decr(a *[16]byte) {
	for i := 15; i >= 0; i-- {
		a[i]--
		if a[i] != 0xff {
			return
		}
	}
}
