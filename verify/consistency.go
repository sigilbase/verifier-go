package verify

import (
	"encoding/hex"
	"fmt"

	"github.com/sigilbase/verifier-go/internal/bundle"
	"github.com/sigilbase/verifier-go/internal/cjson"
	"github.com/sigilbase/verifier-go/internal/merkle"
)

// checkConsistencyFile is the consistency.json section of verify_bundle:
// the cumulative tree states the exporter recorded, checked against the
// roots captured as the events streamed past.
func (r *run) checkConsistencyFile(b bundle.Reader, rangeFrom, rangeTo int64, rootAt map[int64]string) *hardError {
	if !b.IsFile("consistency.json") || rangeFrom != 1 {
		return nil
	}
	r.info("Checking consistency.json (cumulative tree states)...")

	doc, herr := decodeOptional(b, "consistency.json")
	if herr != nil {
		return herr
	}
	finalRoot, haveFinal := rootAt[rangeTo]
	if !haveFinal || !isObject(doc) {
		return nil
	}

	if lower(text(doc.Field("root"))) != finalRoot {
		r.report("consistency.json: the cumulative root does not recompute from the events", ResultContent)
	}

	for _, state := range iterValues(doc.Field("checkpoint_states")) {
		size := state.Field("tree_size")
		if !isInt(size) || size.Int < 1 || size.Int > rangeTo {
			r.report("consistency.json: a checkpoint state has an invalid tree_size", ResultContent)
			continue
		}
		stateRoot, ok := rootAt[size.Int]
		if !ok || lower(text(state.Field("root"))) != stateRoot {
			r.report(fmt.Sprintf("consistency.json: the recorded root for tree_size %d does not recompute", size.Int), ResultContent)
		}
	}

	if proof := doc.Field("proof"); isObject(proof) {
		var nodes [][]byte
		for _, h := range arrayCast(proof.Field("nodes")) {
			if isString(h) {
				if node, ok := hexBytes(h.Str); ok {
					nodes = append(nodes, node)
				}
			}
		}
		fromSize := intCast(proof.Field("from_tree_size"))
		toSize := intCast(proof.Field("to_tree_size"))
		fromRoot, haveFrom := rootAt[fromSize]
		valid := false
		if fromSize >= 1 && toSize == rangeTo && haveFrom {
			fromRaw, _ := hexBytes(fromRoot)
			toRaw, _ := hexBytes(finalRoot)
			valid = merkle.ConsistencyVerify(int(fromSize), int(toSize), fromRaw, toRaw, nodes)
		}
		if !valid {
			r.report("consistency.json: the recorded consistency proof does not verify", ResultContent)
		}
	}
	return nil
}

// ConsistencyBundles proves one export extends another: RFC 6962
// consistency over the cumulative tree of entry hashes, from two bundles
// that both start at sequence 1 (verify.php's --consistency <old> <new>).
func ConsistencyBundles(oldPath, newPath string, opts Options) *Report {
	r := newRun(&opts)
	rep := r.newReport()
	rep.Mode = "consistency-bundles"
	rep.BundleSHA256 = []PathHash{pathHash(oldPath), pathHash(newPath)}

	r.info("Mode:   consistency between two bundles")
	r.info(fmt.Sprintf("=== Old bundle: %s ===", oldPath))
	old, herr := r.verifyBundle(oldPath, opts.SkipAnchors, nil, nil)
	if herr != nil {
		return r.finishHard(rep, herr)
	}
	r.info(fmt.Sprintf("=== New bundle: %s ===", newPath))
	// The proof from the old size is built as the new bundle's leaves
	// stream past; verify.php holds every leaf instead.
	newer, herr := r.verifyBundle(newPath, opts.SkipAnchors, &walkOptions{proofFrom: old.rangeTo, wantedRootSizes: []int64{old.rangeTo}}, nil)
	if herr != nil {
		return r.finishHard(rep, herr)
	}

	r.info("Checking consistency (RFC 6962)...")
	if old.streamID != newer.streamID {
		r.report("the bundles are for different streams", ResultContent)
	}
	if old.rangeFrom != 1 || newer.rangeFrom != 1 {
		r.report("consistency requires both bundles to start at sequence 1 (cumulative roots are only computable from the full log)", ResultContent)
	}
	if old.rangeTo > newer.rangeTo {
		r.report("the old bundle covers more events than the new one - pass the older bundle first", ResultContent)
	}

	var consistency *ConsistencyInfo
	if len(r.failures) == 0 {
		// With no failures every event contributed its leaf in order, so the
		// old bundle's root over its leaves is its cumulative root at
		// range_to, and the new bundle's root over its first old.range_to
		// leaves is the root captured at that size.
		oldRoot, okOld := old.cumulativeRoots[old.rangeTo]
		newRoot, okNew := newer.cumulativeRoots[newer.rangeTo]
		prefixRoot, okPrefix := newer.cumulativeRoots[old.rangeTo]
		switch {
		case !okOld || !okNew || !okPrefix || !newer.proofBuilt:
			r.report("internal error: the cumulative roots needed for the consistency proof were not captured", ResultContent)
		case oldRoot != prefixRoot:
			r.report(fmt.Sprintf("the new bundle does NOT extend the old one: its first %d entries hash to a different root - history diverged", old.rangeTo), ResultContent)
		default:
			oldRaw, _ := hexBytes(oldRoot)
			newRaw, _ := hexBytes(newRoot)
			if !merkle.ConsistencyVerify(int(old.rangeTo), int(newer.rangeTo), oldRaw, newRaw, newer.proofNodes) {
				r.report("internal error: the generated consistency proof does not verify", ResultContent)
			} else {
				consistency = &ConsistencyInfo{
					Old:        TreeState{TreeSize: old.rangeTo, Root: oldRoot},
					New:        TreeState{TreeSize: newer.rangeTo, Root: newRoot},
					ProofNodes: len(newer.proofNodes),
				}
				r.info(fmt.Sprintf("  old  tree_size=%d root=%s", old.rangeTo, oldRoot))
				r.info(fmt.Sprintf("  new  tree_size=%d root=%s", newer.rangeTo, newRoot))
				r.info(fmt.Sprintf("  proof %d node(s) verified", len(newer.proofNodes)))
			}
		}
	}

	rep.Bundles = []BundleInfo{
		{Path: oldPath, Stream: old.streamID, Range: Range{From: old.rangeFrom, To: old.rangeTo}},
		{Path: newPath, Stream: newer.streamID, Range: Range{From: newer.rangeFrom, To: newer.rangeTo}},
	}
	rep.Consistency = consistency
	return r.finish(rep, r.results.exitCode())
}

// ConsistencyRecorded proves a bundle extends a previously recorded tree
// state (verify.php's --consistency <bundle> --root <hex> --size <n>).
// root is used lowercased, as the command line does; size is the value
// after PHP's (int) cast of the argument.
func ConsistencyRecorded(path string, root string, size int64, opts Options) *Report {
	r := newRun(&opts)
	rep := r.newReport()
	rep.Mode = "consistency-recorded-root"
	rep.BundleSHA256 = []PathHash{pathHash(path)}
	recordedRoot := lower(root)

	r.info("Mode:   consistency against a recorded root")
	r.info(fmt.Sprintf("Bundle: %s", path))
	result, herr := r.verifyBundle(path, opts.SkipAnchors, &walkOptions{wantedRootSizes: []int64{size}}, nil)
	if herr != nil {
		return r.finishHard(rep, herr)
	}

	r.info("Checking consistency (RFC 6962)...")
	switch {
	case result.rangeFrom != 1:
		r.report("consistency requires the bundle to start at sequence 1", ResultContent)
	case size < 1 || size > result.rangeTo:
		r.report(fmt.Sprintf("the recorded size %d is outside this bundle's range", size), ResultContent)
	case !isHex64(recordedRoot):
		r.report("the recorded root is not a 64-character hex hash", ResultContent)
	default:
		prefixRoot := result.cumulativeRoots[size]
		if recordedRoot != prefixRoot {
			r.report(fmt.Sprintf("this bundle does NOT extend the recorded state: its first %d entries hash to %s, not the recorded root", size, prefixRoot), ResultContent)
		} else {
			r.info(fmt.Sprintf("  recorded tree_size=%d root=%s - matches this bundle's prefix", size, recordedRoot))
		}
	}

	rep.Bundle = &BundleInfo{Path: path, Stream: result.streamID, Range: Range{From: result.rangeFrom, To: result.rangeTo}}
	rep.Recorded = &TreeState{TreeSize: size, Root: recordedRoot}
	return r.finish(rep, r.results.exitCode())
}

var _ = hex.EncodeToString
var _ = cjson.Null
