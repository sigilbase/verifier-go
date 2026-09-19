package merkle

import (
	"crypto/subtle"
	"errors"
)

// ErrOldSizeOutOfRange is returned where verify.php's consistency_proof
// throws: the old size must be at least 1 and at most the new size.
var ErrOldSizeOutOfRange = errors.New("old size out of range for consistency proof")

// ConsistencyProof is the RFC 6962 section 2.1.2 proof from the first
// oldSize leaves to the whole tree, as raw node hashes in the order
// verify.php's consistency_proof produces them. An empty proof means the two
// trees are the same size.
func ConsistencyProof(leaves [][]byte, oldSize int) ([][]byte, error) {
	newSize := len(leaves)
	if oldSize < 1 || oldSize > newSize {
		return nil, ErrOldSizeOutOfRange
	}
	if oldSize == newSize {
		return [][]byte{}, nil
	}
	return subproof(oldSize, leaves, true), nil
}

// subproof mirrors consistency_subproof: descend into the half that holds
// the old tree's boundary, appending the root of the other half on the way
// back up; when the old tree is not a complete subtree at the boundary, its
// own root is the first node.
func subproof(oldSize int, leaves [][]byte, oldTreeComplete bool) [][]byte {
	count := len(leaves)
	if oldSize == count {
		if oldTreeComplete {
			return [][]byte{}
		}
		return [][]byte{root(leaves)}
	}

	split := SplitPoint(count)

	if oldSize <= split {
		proof := subproof(oldSize, leaves[:split], oldTreeComplete)
		return append(proof, root(leaves[split:]))
	}

	proof := subproof(oldSize-split, leaves[split:], false)
	return append(proof, root(leaves[:split]))
}

// ConsistencyVerify is RFC 9162 section 2.1.4.2 exactly as verify.php's
// consistency_verify, including its behaviour on odd input: roots and proof
// nodes are arbitrary byte strings and a node of the wrong length simply
// fails to match, an old size below 1 or above the new size is false, equal
// sizes require an empty proof and equal roots, and any other case requires
// a non-empty proof. Comparisons use constant-time equality, which like
// PHP's hash_equals is false for strings of different length.
func ConsistencyVerify(oldSize, newSize int, oldRoot, newRoot []byte, proof [][]byte) bool {
	if oldSize < 1 || newSize < oldSize {
		return false
	}
	if oldSize == newSize {
		return len(proof) == 0 && equal(oldRoot, newRoot)
	}
	if len(proof) == 0 {
		return false
	}

	// Copy so the caller's slice is never reshaped by the unshift below.
	nodes := make([][]byte, 0, len(proof)+1)
	if oldSize&(oldSize-1) == 0 {
		// A complete old tree: its root is the first node of the path.
		nodes = append(nodes, oldRoot)
	}
	nodes = append(nodes, proof...)

	fn := oldSize - 1
	sn := newSize - 1

	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	fr := nodes[0]
	sr := fr

	for _, node := range nodes[1:] {
		if sn == 0 {
			return false
		}

		if fn&1 == 1 || fn == sn {
			fr = NodeHash(node, fr)
			sr = NodeHash(node, sr)

			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, node)
		}

		fn >>= 1
		sn >>= 1
	}

	return sn == 0 && equal(oldRoot, fr) && equal(newRoot, sr)
}

func equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Range is a half-open run of leaf indexes [From, To).
type Range struct {
	From, To int
}

// ProofRanges lists, in proof order, the leaf ranges whose Merkle roots are
// the nodes ConsistencyProof would return for a tree of newSize leaves and
// an old size of oldSize. It follows the same recursion as subproof, but
// records where each appended subtree sits instead of hashing it, so the
// nodes can be built while the leaves stream past. The ranges are pairwise
// disjoint: each is a sibling of the descent path, or the final subtree
// the descent ends in.
func ProofRanges(oldSize, newSize int) ([]Range, error) {
	if oldSize < 1 || oldSize > newSize {
		return nil, ErrOldSizeOutOfRange
	}
	if oldSize == newSize {
		return []Range{}, nil
	}
	return subranges(oldSize, 0, newSize, true), nil
}

func subranges(oldSize, start, count int, oldTreeComplete bool) []Range {
	if oldSize == count {
		if oldTreeComplete {
			return []Range{}
		}
		return []Range{{From: start, To: start + count}}
	}

	split := SplitPoint(count)

	if oldSize <= split {
		ranges := subranges(oldSize, start, split, oldTreeComplete)
		return append(ranges, Range{From: start + split, To: start + count})
	}

	ranges := subranges(oldSize-split, start+split, count-split, false)
	return append(ranges, Range{From: start, To: start + split})
}

// Collector builds a consistency proof from a stream of leaves without
// holding them: one Stack per proof range, fed as the leaves go past in
// order. This is what lets --consistency run over a bundle of any size.
type Collector struct {
	newSize int
	ranges  []Range
	stacks  []Stack
	// order holds the range indexes sorted by From, so a streaming cursor
	// can find the range a leaf belongs to without scanning.
	order  []int
	cursor int
	count  int
}

// NewCollector prepares a collector for a proof from oldSize to newSize.
func NewCollector(oldSize, newSize int) (*Collector, error) {
	ranges, err := ProofRanges(oldSize, newSize)
	if err != nil {
		return nil, err
	}
	order := make([]int, len(ranges))
	for i := range order {
		order[i] = i
	}
	// Insertion sort by From: the number of ranges is O(log n).
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && ranges[order[j]].From < ranges[order[j-1]].From; j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
	return &Collector{
		newSize: newSize,
		ranges:  ranges,
		stacks:  make([]Stack, len(ranges)),
		order:   order,
	}, nil
}

// Append feeds the next leaf in tree order (index 0 first). Leaves beyond
// newSize are ignored: they belong to no range of the proof.
func (c *Collector) Append(leafData []byte) {
	index := c.count
	c.count++

	for c.cursor < len(c.order) && index >= c.ranges[c.order[c.cursor]].To {
		c.cursor++
	}
	if c.cursor >= len(c.order) {
		return
	}
	r := c.ranges[c.order[c.cursor]]
	if index >= r.From && index < r.To {
		c.stacks[c.order[c.cursor]].Append(leafData)
	}
}

// ErrIncomplete is returned by Nodes when fewer than newSize leaves were
// appended, so a proof is never emitted over a truncated tree.
var ErrIncomplete = errors.New("consistency proof collector has not seen every leaf")

// Nodes returns the proof nodes in the order ConsistencyProof would return
// them.
func (c *Collector) Nodes() ([][]byte, error) {
	if c.count < c.newSize {
		return nil, ErrIncomplete
	}
	nodes := make([][]byte, len(c.ranges))
	for i := range c.ranges {
		hash, ok := c.stacks[i].Root()
		if !ok {
			return nil, ErrIncomplete
		}
		nodes[i] = hash
	}
	return nodes, nil
}
