package merkle

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// distinctLeaves produces n distinct 32-byte leaves.
func distinctLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		sum := sha256.Sum256([]byte(fmt.Sprintf("leaf-%d", i+1)))
		leaves[i] = sum[:]
	}
	return leaves
}

// rfc6962Leaves is the reference leaf set from RFC 6962 section 2.1.
func rfc6962Leaves(t *testing.T) [][]byte {
	t.Helper()
	var leaves [][]byte
	for _, h := range []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"} {
		leaves = append(leaves, mustHex(t, h))
	}
	return leaves
}

func TestRootMatchesRFC6962Reference(t *testing.T) {
	leaves := rfc6962Leaves(t)
	// The roots over the first 1..8 reference leaves, as published with the
	// Certificate Transparency reference implementation and as verify.php's
	// merkle_root computes them (checked directly against verify.php when
	// this test was written).
	expected := []string{
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	for n, want := range expected {
		got, err := Root(leaves[:n+1])
		if err != nil {
			t.Fatalf("Root over %d leaves: %v", n+1, err)
		}
		if hex.EncodeToString(got) != want {
			t.Errorf("Root over %d leaves = %x; want %s", n+1, got, want)
		}
		var s Stack
		for _, leaf := range leaves[:n+1] {
			s.Append(leaf)
		}
		stackRoot, ok := s.Root()
		if !ok || hex.EncodeToString(stackRoot) != want {
			t.Errorf("Stack over %d leaves = %x, %v; want %s", n+1, stackRoot, ok, want)
		}
	}

	all, err := Root(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(all) != "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328" {
		t.Errorf("Root over all 8 reference leaves = %x", all)
	}
	var s Stack
	for _, leaf := range leaves {
		s.Append(leaf)
	}
	if got, _ := s.Root(); !bytes.Equal(got, all) {
		t.Errorf("Stack over all 8 reference leaves = %x; want %x", got, all)
	}
	if s.Len() != 8 {
		t.Errorf("Stack.Len() = %d; want 8", s.Len())
	}
}

func TestRootRejectsZeroLeaves(t *testing.T) {
	if _, err := Root(nil); err != ErrNoLeaves {
		t.Errorf("Root(nil) error = %v; want ErrNoLeaves", err)
	}
	var s Stack
	if _, ok := s.Root(); ok {
		t.Errorf("empty Stack.Root() reported a root")
	}
}

func TestSplitPoint(t *testing.T) {
	cases := map[int]int{2: 1, 3: 2, 4: 2, 5: 4, 8: 4, 9: 8, 16: 8, 17: 16, 1000: 512}
	for n, want := range cases {
		if got := SplitPoint(n); got != want {
			t.Errorf("SplitPoint(%d) = %d; want %d", n, got, want)
		}
	}
}

func TestMerkleRootVector(t *testing.T) {
	// Hard-coded guard for the golden vector.
	leaves := [][]byte{
		mustHex(t, "234c2a2cd7e937b336639e5a691b4420f3ffd0b7ab5c9b9e3bd4c3573184d98c"),
		mustHex(t, "5b92761f6637911706488d705b451b84c3764664a3a9f33bc5b04943973f3c51"),
	}
	got, err := Root(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "7d1f643ed662fe16fc0eb2715d5a33c70ddf562c2eac24d66504c53a7375424e" {
		t.Errorf("vector root = %x", got)
	}

	// The same vector read from the file, so the file and the code cannot drift.
	raw, err := os.ReadFile("../../vectors/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors struct {
		MerkleRoot struct {
			Leaves           []string `json:"leaves"`
			Root             string   `json:"root"`
			RFC6962Reference []struct {
				Leaves int    `json:"leaves"`
				Root   string `json:"root"`
			} `json:"rfc6962_reference"`
		} `json:"merkle_root"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	var fileLeaves [][]byte
	for _, h := range vectors.MerkleRoot.Leaves {
		fileLeaves = append(fileLeaves, mustHex(t, h))
	}
	fileRoot, err := Root(fileLeaves)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(fileRoot) != vectors.MerkleRoot.Root {
		t.Errorf("vectors.json merkle_root: got %x, file says %s", fileRoot, vectors.MerkleRoot.Root)
	}
}

// TestVectorsFileRFC6962Reference holds the rfc6962_reference entries in
// vectors/vectors.json to the roots this package (and verify.php's
// merkle_root, which agrees byte for byte) computes over the standard
// reference leaves. A failure here means the vector file is wrong, not the
// code: TestRootMatchesRFC6962Reference pins the mathematics independently.
func TestVectorsFileRFC6962Reference(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors struct {
		MerkleRoot struct {
			RFC6962Reference []struct {
				Leaves int    `json:"leaves"`
				Root   string `json:"root"`
			} `json:"rfc6962_reference"`
		} `json:"merkle_root"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	reference := rfc6962Leaves(t)
	for _, ref := range vectors.MerkleRoot.RFC6962Reference {
		if ref.Leaves < 1 || ref.Leaves > len(reference) {
			t.Errorf("vectors.json rfc6962_reference names %d leaves; the reference set has %d", ref.Leaves, len(reference))
			continue
		}
		r, err := Root(reference[:ref.Leaves])
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(r) != ref.Root {
			t.Errorf("vectors.json rfc6962_reference for %d leaves says %s; verify.php and this package compute %x", ref.Leaves, ref.Root, r)
		}
	}
}

func TestStackEqualsRecursiveRootForEverySize(t *testing.T) {
	leaves := distinctLeaves(300)
	var s Stack
	for n := 1; n <= 300; n++ {
		s.Append(leaves[n-1])
		want, err := Root(leaves[:n])
		if err != nil {
			t.Fatal(err)
		}
		got, ok := s.Root()
		if !ok || !bytes.Equal(got, want) {
			t.Fatalf("size %d: stack root %x, recursive root %x", n, got, want)
		}
		if s.Len() != n {
			t.Fatalf("size %d: Len() = %d", n, s.Len())
		}
	}
	s.Reset()
	if s.Len() != 0 {
		t.Errorf("Reset left Len() = %d", s.Len())
	}
	if _, ok := s.Root(); ok {
		t.Errorf("Reset stack still has a root")
	}
	s.Append(leaves[0])
	want, _ := Root(leaves[:1])
	if got, _ := s.Root(); !bytes.Equal(got, want) {
		t.Errorf("stack after Reset does not restart cleanly")
	}
}

func TestConsistencyProofRoundTripsAtEverySizePair(t *testing.T) {
	leaves := distinctLeaves(24)
	for newSize := 1; newSize <= 24; newSize++ {
		tree := leaves[:newSize]
		newRoot, err := Root(tree)
		if err != nil {
			t.Fatal(err)
		}
		for oldSize := 1; oldSize <= newSize; oldSize++ {
			proof, err := ConsistencyProof(tree, oldSize)
			if err != nil {
				t.Fatalf("%d -> %d: %v", oldSize, newSize, err)
			}
			oldRoot, err := Root(tree[:oldSize])
			if err != nil {
				t.Fatal(err)
			}
			if !ConsistencyVerify(oldSize, newSize, oldRoot, newRoot, proof) {
				t.Errorf("consistency failed for %d -> %d", oldSize, newSize)
			}
			if oldSize == newSize && len(proof) != 0 {
				t.Errorf("%d -> %d: proof should be empty", oldSize, newSize)
			}

			// A wrong old root must fail.
			wrong := sha256.Sum256([]byte("wrong"))
			if ConsistencyVerify(oldSize, newSize, wrong[:], newRoot, proof) {
				t.Errorf("%d -> %d: accepted a wrong old root", oldSize, newSize)
			}
			if ConsistencyVerify(oldSize, newSize, oldRoot, wrong[:], proof) {
				t.Errorf("%d -> %d: accepted a wrong new root", oldSize, newSize)
			}

			// A tampered node must fail.
			if len(proof) > 0 {
				tampered := make([][]byte, len(proof))
				for i := range proof {
					tampered[i] = append([]byte(nil), proof[i]...)
				}
				tampered[len(tampered)/2][0] ^= 0x01
				if ConsistencyVerify(oldSize, newSize, oldRoot, newRoot, tampered) {
					t.Errorf("%d -> %d: accepted a tampered proof node", oldSize, newSize)
				}
			}
		}
	}
}

func TestConsistencyVerifyOddInputs(t *testing.T) {
	leaves := distinctLeaves(3)
	r, _ := Root(leaves)
	x := LeafHash([]byte("a"))
	y := sha256.Sum256([]byte("x"))

	if ConsistencyVerify(1, 2, x, y[:], [][]byte{[]byte("short")}) {
		t.Errorf("a short node verified")
	}
	if !ConsistencyVerify(3, 3, r, r, nil) {
		t.Errorf("equal sizes with equal roots and no proof must verify")
	}
	if ConsistencyVerify(3, 3, r, r, [][]byte{r}) {
		t.Errorf("equal sizes with a non-empty proof must not verify")
	}
	if ConsistencyVerify(0, 3, r, r, nil) {
		t.Errorf("old size 0 must not verify")
	}
	if ConsistencyVerify(4, 3, r, r, nil) {
		t.Errorf("old size beyond new size must not verify")
	}
	if ConsistencyVerify(1, 3, r, r, [][]byte{}) {
		t.Errorf("a growing tree with an empty proof must not verify")
	}
	if ConsistencyVerify(1, 2, nil, nil, [][]byte{nil}) {
		t.Errorf("empty roots and nodes must not verify")
	}
	// A proof that is far too long must fail rather than panic.
	long := make([][]byte, 40)
	for i := range long {
		long[i] = r
	}
	if ConsistencyVerify(2, 5, r, r, long) {
		t.Errorf("an over-long proof verified")
	}

	if _, err := ConsistencyProof(leaves, 0); err != ErrOldSizeOutOfRange {
		t.Errorf("ConsistencyProof old size 0: %v", err)
	}
	if _, err := ConsistencyProof(leaves, 4); err != ErrOldSizeOutOfRange {
		t.Errorf("ConsistencyProof old size 4 of 3: %v", err)
	}
}

func TestConsistencyVerifyDoesNotReshapeCallerProof(t *testing.T) {
	leaves := distinctLeaves(8)
	oldRoot, _ := Root(leaves[:4])
	newRoot, _ := Root(leaves)
	proof, _ := ConsistencyProof(leaves, 4)
	before := len(proof)
	copyOfProof := append([][]byte(nil), proof...)
	if !ConsistencyVerify(4, 8, oldRoot, newRoot, proof) {
		t.Fatal("proof should verify")
	}
	if len(proof) != before {
		t.Errorf("proof slice length changed from %d to %d", before, len(proof))
	}
	for i := range proof {
		if !bytes.Equal(proof[i], copyOfProof[i]) {
			t.Errorf("proof node %d was modified", i)
		}
	}
}

func TestCollectorMatchesConsistencyProof(t *testing.T) {
	leaves := distinctLeaves(64)
	for newSize := 1; newSize <= 64; newSize++ {
		tree := leaves[:newSize]
		newRoot, _ := Root(tree)
		for oldSize := 1; oldSize <= newSize; oldSize++ {
			want, err := ConsistencyProof(tree, oldSize)
			if err != nil {
				t.Fatal(err)
			}
			collector, err := NewCollector(oldSize, newSize)
			if err != nil {
				t.Fatal(err)
			}
			for _, leaf := range tree {
				collector.Append(leaf)
			}
			got, err := collector.Nodes()
			if err != nil {
				t.Fatalf("%d -> %d: %v", oldSize, newSize, err)
			}
			if len(got) != len(want) {
				t.Fatalf("%d -> %d: collector produced %d nodes, proof has %d", oldSize, newSize, len(got), len(want))
			}
			for i := range want {
				if !bytes.Equal(got[i], want[i]) {
					t.Fatalf("%d -> %d: node %d differs", oldSize, newSize, i)
				}
			}
			oldRoot, _ := Root(tree[:oldSize])
			if !ConsistencyVerify(oldSize, newSize, oldRoot, newRoot, got) {
				t.Errorf("%d -> %d: collector nodes do not verify", oldSize, newSize)
			}

			// Ranges are pairwise disjoint and cover exactly the leaves the
			// proof needs.
			ranges, _ := ProofRanges(oldSize, newSize)
			for i := range ranges {
				if ranges[i].From >= ranges[i].To || ranges[i].From < 0 || ranges[i].To > newSize {
					t.Errorf("%d -> %d: bad range %+v", oldSize, newSize, ranges[i])
				}
				for j := range ranges {
					if i != j && ranges[i].From < ranges[j].To && ranges[j].From < ranges[i].To {
						t.Errorf("%d -> %d: ranges %+v and %+v overlap", oldSize, newSize, ranges[i], ranges[j])
					}
				}
			}
		}
	}
}

func TestCollectorRefusesIncompleteTree(t *testing.T) {
	leaves := distinctLeaves(8)
	collector, err := NewCollector(3, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range leaves[:7] {
		collector.Append(leaf)
	}
	if _, err := collector.Nodes(); err != ErrIncomplete {
		t.Errorf("Nodes on 7 of 8 leaves: %v; want ErrIncomplete", err)
	}
	if _, err := NewCollector(0, 8); err != ErrOldSizeOutOfRange {
		t.Errorf("NewCollector(0, 8): %v", err)
	}
	if _, err := NewCollector(9, 8); err != ErrOldSizeOutOfRange {
		t.Errorf("NewCollector(9, 8): %v", err)
	}
	same, err := NewCollector(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range leaves {
		same.Append(leaf)
	}
	nodes, err := same.Nodes()
	if err != nil || len(nodes) != 0 {
		t.Errorf("equal sizes: nodes %v, err %v; want empty, nil", nodes, err)
	}
}

// inclusionPath derives a leaf's audit path from the recursive structure.
func inclusionPath(leaves [][]byte, index int) []Step {
	if len(leaves) == 1 {
		return nil
	}
	split := SplitPoint(len(leaves))
	if index < split {
		path := inclusionPath(leaves[:split], index)
		return append(path, Step{Sibling: root(leaves[split:]), Left: false})
	}
	path := inclusionPath(leaves[split:], index-split)
	return append(path, Step{Sibling: root(leaves[:split]), Left: true})
}

func TestAuditPathRebuildsRoot(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 13} {
		leaves := distinctLeaves(n)
		want, _ := Root(leaves)
		for i := range leaves {
			path := inclusionPath(leaves, i)
			got := AuditPath(leaves[i], path)
			if !bytes.Equal(got, want) {
				t.Errorf("%d leaves, index %d: audit path gives %x, root is %x", n, i, got, want)
			}
			if len(path) > 0 {
				// Flipping a side, or a sibling byte, must break the fold.
				flipped := append([]Step(nil), path...)
				flipped[0].Left = !flipped[0].Left
				if bytes.Equal(AuditPath(leaves[i], flipped), want) && n > 1 {
					t.Errorf("%d leaves, index %d: a flipped side still rebuilt the root", n, i)
				}
			}
		}
	}
	// A single leaf with no path is just the leaf hash.
	leaf := distinctLeaves(1)[0]
	if !bytes.Equal(AuditPath(leaf, nil), LeafHash(leaf)) {
		t.Errorf("empty path did not yield the leaf hash")
	}
}

// corpusValid reads events.ndjson entry hashes and consistency.json from
// the conformance corpus fixture.
func corpusValid(t *testing.T) (leaves [][]byte, consistency struct {
	Root             string `json:"root"`
	CheckpointStates []struct {
		TreeSize int    `json:"tree_size"`
		Root     string `json:"root"`
	} `json:"checkpoint_states"`
	Proof struct {
		FromTreeSize int      `json:"from_tree_size"`
		ToTreeSize   int      `json:"to_tree_size"`
		Nodes        []string `json:"nodes"`
	} `json:"proof"`
}) {
	t.Helper()
	archive, err := zip.OpenReader("../../corpus/valid.zip")
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer archive.Close()

	read := func(name string) []byte {
		for _, f := range archive.File {
			if f.Name == name {
				rc, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				defer rc.Close()
				data, err := io.ReadAll(rc)
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
		}
		t.Fatalf("corpus has no %s", name)
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(read("events.ndjson")))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event struct {
			EntryHash string `json:"entry_hash"`
		}
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, mustHex(t, event.EntryHash))
	}
	if err := json.Unmarshal(read("consistency.json"), &consistency); err != nil {
		t.Fatal(err)
	}
	return leaves, consistency
}

func TestCorpusValidConsistency(t *testing.T) {
	leaves, consistency := corpusValid(t)
	if len(leaves) != 40 {
		t.Fatalf("corpus valid.zip has %d events; want 40", len(leaves))
	}
	if consistency.Proof.FromTreeSize != 10 || consistency.Proof.ToTreeSize != 40 || len(consistency.Proof.Nodes) != 6 {
		t.Fatalf("unexpected recorded proof: from %d to %d with %d nodes", consistency.Proof.FromTreeSize, consistency.Proof.ToTreeSize, len(consistency.Proof.Nodes))
	}

	root10, _ := Root(leaves[:10])
	root40, _ := Root(leaves)
	if hex.EncodeToString(root10) != "4724aed3af896157efa69da5ecca3c6b41993ece4d77f4c855d38185396c50fc" {
		t.Errorf("root over first 10 = %x", root10)
	}
	if hex.EncodeToString(root40) != "59c999765f4cfdfebf062ed8ae18e2d7d46a1a86d09490d024f87238e5a87ff4" {
		t.Errorf("root over all 40 = %x", root40)
	}
	if consistency.Root != hex.EncodeToString(root40) {
		t.Errorf("consistency.json root %s differs from rebuilt %x", consistency.Root, root40)
	}
	for _, state := range consistency.CheckpointStates {
		r, err := Root(leaves[:state.TreeSize])
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(r) != state.Root {
			t.Errorf("checkpoint state tree_size %d: rebuilt %x, recorded %s", state.TreeSize, r, state.Root)
		}
		var s Stack
		for _, leaf := range leaves[:state.TreeSize] {
			s.Append(leaf)
		}
		if got, _ := s.Root(); !bytes.Equal(got, r) {
			t.Errorf("checkpoint state tree_size %d: stack root differs", state.TreeSize)
		}
	}

	var nodes [][]byte
	for _, h := range consistency.Proof.Nodes {
		nodes = append(nodes, mustHex(t, h))
	}
	if !ConsistencyVerify(10, 40, root10, root40, nodes) {
		t.Errorf("recorded consistency proof does not verify")
	}

	generated, err := ConsistencyProof(leaves, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != len(nodes) {
		t.Fatalf("generated proof has %d nodes; recorded has %d", len(generated), len(nodes))
	}
	for i := range nodes {
		if !bytes.Equal(generated[i], nodes[i]) {
			t.Errorf("proof node %d: generated %x, recorded %x", i, generated[i], nodes[i])
		}
	}

	collector, err := NewCollector(10, 40)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range leaves {
		collector.Append(leaf)
	}
	streamed, err := collector.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	for i := range nodes {
		if !bytes.Equal(streamed[i], nodes[i]) {
			t.Errorf("streamed node %d: %x, recorded %x", i, streamed[i], nodes[i])
		}
	}
}
