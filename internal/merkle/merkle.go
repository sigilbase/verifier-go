// Package merkle implements the RFC 6962 Merkle tree exactly as verify.php
// computes it: the same leaf and node prefixes, the same split point, the
// same Certificate Transparency hash stack, the same consistency proof
// generation (RFC 6962 section 2.1.2) and verification (RFC 9162 section
// 2.1.4.2), and the same audit-path fold. The two verifiers are held to each
// other fixture by fixture, so every function here mirrors the PHP function
// it names rather than a tidier formulation of the same mathematics.
package merkle

import (
	"crypto/sha256"
	"errors"
)

// LeafHash is SHA-256(0x00 || data), the RFC 6962 leaf hash. Leaves in a
// bundle are the raw 32-byte entry hashes, but the function accepts any
// bytes because the reference vectors use short arbitrary leaves.
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// NodeHash is SHA-256(0x01 || left || right), the RFC 6962 interior node
// hash. The children are not required to be 32 bytes: verify.php feeds
// whatever bytes a proof supplies, and a node of the wrong length must
// produce a mismatch rather than a panic.
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// SplitPoint is the largest power of two strictly smaller than n, the RFC
// 6962 split for a tree of n > 1 leaves (merkle_split_point in verify.php).
func SplitPoint(n int) int {
	split := 1
	for split*2 < n {
		split *= 2
	}
	return split
}

// ErrNoLeaves is returned where verify.php throws for an empty tree.
var ErrNoLeaves = errors.New("cannot build a Merkle tree with zero leaves")

// Root is the recursive RFC 6962 root over raw leaves (merkle_root in
// verify.php). It holds every leaf, so ordinary verification uses Stack
// instead; Root exists for the vectors and for --consistency, which needs
// the whole tree anyway.
func Root(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, ErrNoLeaves
	}
	return root(leaves), nil
}

func root(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return LeafHash(leaves[0])
	}
	split := SplitPoint(len(leaves))
	return NodeHash(root(leaves[:split]), root(leaves[split:]))
}

// Stack is the Certificate Transparency hash stack (merkle_stack_append and
// merkle_stack_root in verify.php): append leaves one at a time and read the
// RFC 6962 root over everything appended so far, in memory proportional to
// log(n) rather than n.
//
// The stack holds one perfect subtree root per set bit of the leaf count,
// sizes strictly descending, and the root folds them smallest-first. Because
// RFC 6962 splits at the largest power of two strictly below n, that fold is
// byte-identical to Root over the same leaves; the tests hold the two
// together for every size up to 300.
type Stack struct {
	entries []stackEntry
	count   int
}

type stackEntry struct {
	size int
	hash []byte
}

// Append adds the next leaf and merges equal-sized subtrees, exactly as
// merkle_stack_append does.
func (s *Stack) Append(leafData []byte) {
	s.entries = append(s.entries, stackEntry{size: 1, hash: LeafHash(leafData)})
	s.count++

	top := len(s.entries) - 1
	for top > 0 && s.entries[top-1].size == s.entries[top].size {
		merged := stackEntry{
			size: s.entries[top].size * 2,
			hash: NodeHash(s.entries[top-1].hash, s.entries[top].hash),
		}
		s.entries = append(s.entries[:top-1], merged)
		top--
	}
}

// Len is the number of leaves appended since the last Reset.
func (s *Stack) Len() int {
	return s.count
}

// Root is the RFC 6962 root over every leaf appended so far, folding the
// subtree roots smallest-first as merkle_stack_root does. It returns false
// for an empty stack, where verify.php throws.
func (s *Stack) Root() ([]byte, bool) {
	if len(s.entries) == 0 {
		return nil, false
	}
	var hash []byte
	for i := len(s.entries) - 1; i >= 0; i-- {
		if hash == nil {
			hash = append([]byte(nil), s.entries[i].hash...)
		} else {
			hash = NodeHash(s.entries[i].hash, hash)
		}
	}
	return hash, true
}

// Reset empties the stack so it can rebuild the next checkpoint's tree.
func (s *Stack) Reset() {
	s.entries = s.entries[:0]
	s.count = 0
}

// Step is one level of an RFC 6962 inclusion path: the sibling node and
// which side of the current node it sits on.
type Step struct {
	Sibling []byte
	Left    bool
}

// AuditPath folds an inclusion path from a leaf's raw entry hash up to a
// root, exactly as verify.php's declaration_proof_problem does: the leaf is
// prefixed 0x00, then each step hashes NodeHash(sibling, current) when the
// sibling is on the left and NodeHash(current, sibling) when it is on the
// right. The caller compares the result with the checkpoint's root.
func AuditPath(entryHash []byte, path []Step) []byte {
	computed := LeafHash(entryHash)
	for _, step := range path {
		if step.Left {
			computed = NodeHash(step.Sibling, computed)
		} else {
			computed = NodeHash(computed, step.Sibling)
		}
	}
	return computed
}
