// Command sigilbase-verify verifies Sigilbase evidence bundles. It is the
// Go peer of verify.php: the same flags, the same exit codes, the same
// five results, and a --json document that matches verify.php's on every
// corpus fixture apart from the fields that identify which implementation
// ran.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sigilbase/verifier-go/internal/phpcompat"
	"github.com/sigilbase/verifier-go/verify"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `Sigilbase evidence verifier (sigilbase-verify).

usage: sigilbase-verify [options] <bundle.zip | extracted-bundle-directory>
       sigilbase-verify --consistency <old-bundle> <new-bundle>
       sigilbase-verify --consistency <bundle> --root <hex> --size <n>

Options:
  --keys <file>       trust these signing keys instead of the built-in set.
                      Same shape as https://app.sigilbase.io/api/v1/keys
  --tsa-roots <file>  trust these timestamp-authority roots (PEM) instead of
                      the built-in ones
  --skip-anchors      do not validate the RFC 3161 anchors
  --json              one machine-readable JSON document on stdout
  --quiet             no output at all; the exit code is the whole answer
  --print-hashes      also report the sha256 of each bundle file argument
  --help              this text

Results reported: content integrity, signing identity, timestamps, scope,
redactions.

Exit codes:
  0  PASS         every result that was checked holds
  1  FAIL         integrity, redactions or a key window failed
  2  ERROR        usage, unreadable bundle, or an unknown format
  3  UNCONFIRMED  the maths holds, but the signing identity or the
                  timestamps could not be confirmed

What a pass does not prove: that events were true when written (a false
statement is sealed faithfully; tamper-evidence starts at ingestion), that
the exported range is the whole story, what happened between an event
arriving and its checkpoint being sealed, or who a person was (actor is
whatever the writing system claimed). Output makes no legal claim: it
reports what was checked and what was not.
`

// options is the parsed command line, one field per verify.php variable.
type options struct {
	skipAnchors  bool
	consistency  bool
	jsonMode     bool
	quiet        bool
	printHashes  bool
	showHelp     bool
	recordedRoot *string
	recordedSize *int64
	keysFile     *string
	tsaRootsFile *string
	targets      []string
}

// run parses the arguments exactly as verify.php does, including the
// --flag=value forms it accepts, and returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	var o options
	next := func(i *int) string {
		*i++
		if *i < len(args) {
			return args[*i]
		}
		return ""
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--skip-anchors":
			o.skipAnchors = true
		case a == "--consistency":
			o.consistency = true
		case a == "--json":
			o.jsonMode = true
		case a == "--quiet":
			o.quiet = true
		case a == "--print-hashes":
			o.printHashes = true
		case a == "--root":
			v := strings.ToLower(next(&i))
			o.recordedRoot = &v
		case strings.HasPrefix(a, "--root="):
			v := strings.ToLower(a[len("--root="):])
			o.recordedRoot = &v
		case a == "--size":
			v := phpcompat.StringToInt(next(&i))
			o.recordedSize = &v
		case strings.HasPrefix(a, "--size="):
			v := phpcompat.StringToInt(a[len("--size="):])
			o.recordedSize = &v
		case a == "--keys":
			v := next(&i)
			o.keysFile = &v
		case strings.HasPrefix(a, "--keys="):
			v := a[len("--keys="):]
			o.keysFile = &v
		case a == "--tsa-roots":
			v := next(&i)
			o.tsaRootsFile = &v
		case strings.HasPrefix(a, "--tsa-roots="):
			v := a[len("--tsa-roots="):]
			o.tsaRootsFile = &v
		case a == "--help" || a == "-h":
			o.showHelp = true
		case strings.HasPrefix(a, "--"):
			// verify.php stops at the first unknown option, in whatever
			// output mode the flags before it had established.
			return failHard(&o, stdout, stderr, fmt.Sprintf("unknown option [%s]", a), verify.ExitError)
		default:
			o.targets = append(o.targets, a)
		}
	}

	if o.showHelp {
		fmt.Fprint(stdout, usage)
		return verify.ExitPass
	}

	vopts := verify.Options{SkipAnchors: o.skipAnchors, PrintHashes: o.printHashes}
	if o.keysFile != nil {
		set, err := verify.LoadKeyFile(*o.keysFile)
		if err != nil {
			return failHard(&o, stdout, stderr, err.Error(), verify.ExitError)
		}
		vopts.Keys = set
		vopts.KeysSource = "--keys " + *o.keysFile
	}
	if o.tsaRootsFile != nil {
		info, err := os.Stat(*o.tsaRootsFile)
		if err != nil || !info.Mode().IsRegular() {
			return failHard(&o, stdout, stderr, fmt.Sprintf("--tsa-roots file [%s] does not exist", *o.tsaRootsFile), verify.ExitError)
		}
		data, err := os.ReadFile(*o.tsaRootsFile)
		if err != nil {
			return failHard(&o, stdout, stderr, fmt.Sprintf("--tsa-roots file [%s] does not exist", *o.tsaRootsFile), verify.ExitError)
		}
		pem := string(data)
		vopts.TSARoots = &pem
		vopts.TSARootsSource = "--tsa-roots " + *o.tsaRootsFile
	}

	var report *verify.Report
	switch {
	case !o.consistency:
		if len(o.targets) != 1 {
			if !o.quiet && !o.jsonMode {
				fmt.Fprint(stderr, usage)
			}
			return failHard(&o, stdout, stderr, "expected exactly one bundle argument", verify.ExitError)
		}
		report = verify.Bundle(o.targets[0], vopts)
	case len(o.targets) == 2 && o.recordedRoot == nil && o.recordedSize == nil:
		report = verify.ConsistencyBundles(o.targets[0], o.targets[1], vopts)
	case len(o.targets) == 1 && o.recordedRoot != nil && o.recordedSize != nil:
		report = verify.ConsistencyRecorded(o.targets[0], *o.recordedRoot, *o.recordedSize, vopts)
	default:
		if !o.quiet && !o.jsonMode {
			fmt.Fprint(stderr, usage)
		}
		return failHard(&o, stdout, stderr, "invalid combination of arguments", verify.ExitError)
	}

	return emit(&o, report, stdout, stderr)
}

// failHard reports a usage-level failure the way verify.php's fail_hard
// does: the JSON error document in --json mode, one line on stderr
// otherwise, nothing under --quiet.
func failHard(o *options, stdout, stderr io.Writer, message string, code int) int {
	rep := &verify.Report{VerifierName: verify.Name, VerifierVersion: verify.Version, Hard: true, Result: "error", ExitCode: code, Message: message}
	return emit(o, rep, stdout, stderr)
}

// emit writes a report in the requested mode and returns its exit code.
func emit(o *options, rep *verify.Report, stdout, stderr io.Writer) int {
	if o.quiet {
		return rep.ExitCode
	}
	if o.jsonMode {
		out, err := rep.JSON()
		if err != nil {
			fmt.Fprintf(stderr, "ERROR: could not encode the report: %v\n", err)
			return verify.ExitError
		}
		stdout.Write(out)
		return rep.ExitCode
	}
	if rep.Hard {
		fmt.Fprintf(stderr, "%s: %s\n", verify.VerdictWord(rep.ExitCode), rep.Message)
		for _, line := range rep.Log {
			if line.Kind == "fail" || line.Kind == "unconfirmed" || line.Kind == "note" {
				fmt.Fprintf(stderr, "  %s %s\n", strings.ToUpper(line.Kind), line.Text)
			}
		}
		return rep.ExitCode
	}
	fmt.Fprint(stdout, Human(rep))
	return rep.ExitCode
}

// Human renders the report for a person. The first word is the verdict;
// then the account of what was checked, the five results, every signing
// key used and where trust in it came from, each redaction, the
// verifier's identity and, with --print-hashes, each bundle file's hash.
func Human(rep *verify.Report) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	problems := len(rep.Failures)
	switch rep.Mode {
	case "verify":
		switch rep.ExitCode {
		case verify.ExitFail:
			w("FAIL: %d problem(s) found. This bundle does NOT verify.\n", problems)
		case verify.ExitUnconfirmed:
			w("UNCONFIRMED: the maths holds and nothing here has been altered, but this bundle's\norigin is not established (see the results below). It is not evidence of tampering,\nand it is not a pass.\n")
		default:
			w("PASS: every result that was checked holds.\n")
		}
	default:
		if rep.ExitCode == verify.ExitFail {
			w("FAIL: %d problem(s) found. Consistency does NOT hold.\n", problems)
		} else if rep.Mode == "consistency-bundles" {
			w("%s: the new bundle is an append-only extension of the old bundle.\nNothing recorded in the old export was modified, deleted, or reordered in the new one.\n", verify.VerdictWord(rep.ExitCode))
		} else {
			w("%s: this bundle is an append-only extension of the recorded state.\n", verify.VerdictWord(rep.ExitCode))
		}
	}

	w("\nSigilbase evidence verifier %s v%s\n", rep.VerifierName, rep.VerifierVersion)
	switch rep.Mode {
	case "verify":
		w("Bundle: %s\n", rep.Bundle.Path)
	case "consistency-bundles":
		w("Mode:   consistency between two bundles\n")
	case "consistency-recorded-root":
		w("Mode:   consistency against a recorded root\n")
	}
	w("\n")
	for _, line := range rep.Log {
		switch line.Kind {
		case "info":
			w("%s\n", line.Text)
		case "fail", "unconfirmed", "note":
			w("  %s %s\n", strings.ToUpper(line.Kind), line.Text)
		}
	}

	if rep.Mode == "verify" && rep.ExitCode != verify.ExitFail {
		w("\n%d events and %d checkpoints verified for stream %s (%d..%d).\n", rep.Bundle.Events, rep.Bundle.Checkpoints, rep.Bundle.Stream, rep.Bundle.Range.From, rep.Bundle.Range.To)
		w("No event has been modified, deleted, or reordered, and every checkpoint signature is genuine.\n")
		if rep.Bundle.RedactedEvents > 0 {
			w("Redactions: %d payload(s) were destroyed by the tenant, each named by an authenticated declaration in this bundle; their hashes are preserved and the chain is intact.\n", rep.Bundle.RedactedEvents)
		}
	}

	w("\n")
	labels := []struct{ key, label string }{
		{verify.ResultContent, "Content integrity"},
		{verify.ResultIdentity, "Signing identity"},
		{verify.ResultTimestamps, "Timestamps"},
		{verify.ResultScope, "Scope"},
		{verify.ResultRedactions, "Redactions"},
	}
	for _, l := range labels {
		w("  %-18s %s\n", l.label, strings.ToUpper(strings.ReplaceAll(rep.Results.Get(l.key), "_", " ")))
	}

	if len(rep.SigningKeys) > 0 {
		w("\nSigning keys used:\n")
		for _, k := range rep.SigningKeys {
			w("  %s  trust: %s\n", k.Fingerprint, k.Source)
		}
	}

	if rep.ConsistencyState != nil {
		w("\nConsistency state: tree_size=%d root=%s\n", rep.ConsistencyState.TreeSize, rep.ConsistencyState.Root)
		w("Record these two values: a future export can prove it extends this one (--consistency).\n")
	}

	w("\nVerifier: %s v%s sha256 %s\n", rep.VerifierName, rep.VerifierVersion, rep.VerifierSHA256)
	if rep.PrintHashes {
		for _, h := range rep.BundleSHA256 {
			hash := "(directory, not hashed)"
			if h.Hash != nil {
				hash = *h.Hash
			}
			w("Bundle sha256:  %s  %s\n", hash, h.Path)
		}
	}
	return b.String()
}
