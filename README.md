# sigilbase-verify

The Go implementation of the Sigilbase evidence bundle verifier: a static
binary with no third-party code that recomputes every hash and checks every
signature from a bundle's own bytes, so you do not have to trust Sigilbase
(or whoever handed you the bundle) to confirm that nothing was modified,
deleted, or reordered after ingestion.

It is a peer of [`verify.php`](https://github.com/sigilbase/verifier), the
PHP implementation that ships inside every bundle, not a port of it. The
format specification ([FORMAT.md](https://github.com/sigilbase/verifier/blob/main/FORMAT.md)),
the golden vectors and the conformance corpus decide what is correct; both
implementations conform to them, and the release pipeline holds the two to
the same exit code and the same five results on every fixture. A difference
between them is a bug in one of them, treated as critical.

## If you have been handed a bundle

Download the binary for your platform from the
[release page](https://github.com/sigilbase/verifier-go/releases) and check
its hash against `SHA256SUMS` there. Then:

```bash
# 1. Verify the bundle. Exit code 0 and "PASS" mean every check held.
sigilbase-verify the-bundle-you-received.zip

# 2. Record what you ran against what (keep these hashes with your notes).
#    A passing bundle that starts at sequence 1 also prints a consistency
#    root; keep it, and step 3 can prove a later export extends this one.
sigilbase-verify --print-hashes the-bundle-you-received.zip

# 3. Later, prove a newer export extends this one with nothing rewritten.
sigilbase-verify --consistency the-bundle-you-received.zip the-newer-bundle.zip
```

The bundle also contains its own copy of `verify.php`, which needs PHP 8.2
or newer and gives the same answer; running this binary instead removes the
bundle itself from the trust equation entirely.

**Five results.** A verification answers five questions separately,
because what was proved and who proved it are not the same question:

| Result | What it covers |
| --- | --- |
| Content integrity | The hash chain, payload hashes, Merkle roots and checkpoint signatures |
| Signing identity | Whether those signatures are by a key this verifier trusts, sealed inside that key's window |
| Timestamps | The RFC 3161 anchors, against trust roots this verifier carries |
| Scope | The range and completeness the manifest claims |
| Redactions | Whether every absent payload is named by an authenticated declaration |

**What PASS means.** No event in the bundle differs by one byte from what
was sealed; within the exported range nothing was removed, inserted, or
reordered; the sealed checkpoints chain together so a whole period cannot
have been quietly dropped; every seal carries a valid Ed25519 signature;
and the keys that made those signatures are ones this verifier already
trusted. If the bundle carries RFC 3161 anchor tokens, PASS additionally
means independent timestamping authorities whose roots this verifier
carries attested the checkpoints existed at the recorded times.

**What UNCONFIRMED means.** The maths holds and the origin is not
established. The bundle is internally sound - nothing in it has been
altered - and it was signed by a key this verifier does not carry, or its
timestamps could not be tied to a root this verifier carries. That is not
evidence of tampering and it is not a pass: anyone can produce a hash chain
and sign it with a key of their own, so a bundle cannot vouch for whose
keys it carries. You will see it on a bundle from a private deployment, on
a test bundle, and on a bundle somebody rebuilt and re-signed.

**Choosing what to trust.** The binary carries Sigilbase's signing keys,
compiled in from `keys/sigilbase.json` and matched on the public key bytes,
and the roots of the timestamp authorities production anchors use, from
`keys/tsa-roots.pem`. `--keys <file>` replaces the key set entirely, in the
shape of the `/api/v1/keys` response, so you can fetch the keys yourself and
check against what you fetched rather than against what we shipped.
`--tsa-roots <file>` does the same for timestamp authorities. A bundle
anchored by an authority whose root the verifier does not carry fails the
timestamps result until you name that root with `--tsa-roots`; a root that
travels inside the bundle never establishes trust on its own.

**What a failure means.** The output names the first thing that broke - the
exact event sequence or checkpoint and the nature of the problem (chain
break, hash mismatch, missing event, bad signature, checkpoint chain break).
A failing bundle does not verify; treat it as altered until someone explains
otherwise. Exit codes: `0` PASS, `1` FAIL, `2` ERROR (usage, an unreadable
bundle or an unknown format - nothing was verified either way), `3`
UNCONFIRMED.

**Check which verifier you ran.** Every run prints the implementation's
name, version and the sha256 of the binary. Compare them with the release
notes: a verifier is only as trustworthy as the file you actually ran, and
that line is what lets you say which one it was.

**What verification does not prove.** Honesty about limits is part of the
guarantee. It does not prove events were *true* when written - if a system
recorded that a backup succeeded when it did not, the false statement is
sealed faithfully; tamper-evidence starts at ingestion. It does not prove
the exported range is the whole story - whether other streams or periods
exist is an audit-scoping question. It does not cover the minutes between
an event arriving and its checkpoint being sealed. And it does not identify
people: `actor` is whatever the writing system claimed; the record of the
claim is what is protected. The output makes no legal claim: it reports
what was checked and what was not.

## Flags

| Flag | Effect |
| --- | --- |
| `--keys <file>` | trust these signing keys instead of the built-in set |
| `--tsa-roots <file>` | trust these timestamp-authority roots (PEM) instead of the built-in ones |
| `--skip-anchors` | do not validate the RFC 3161 anchors |
| `--json` | one machine-readable document on stdout, described by `result.schema.json` |
| `--quiet` | no output at all; the exit code is the whole answer |
| `--print-hashes` | also report the sha256 of each bundle file argument |
| `--consistency` | two bundles, or one bundle with `--root <hex> --size <n>` |
| `--help` | usage |

The flags, their `--flag=value` forms, the exit codes and the `--json`
document are identical to `verify.php`'s apart from the fields that identify
which implementation ran.

## In a pipeline

`ci/gitlab/verify-bundle.gitlab-ci.yml` is a GitLab CI template and
`integrations/github-action/` a GitHub Action. Each downloads a pinned
release binary, checks it against a sha256 you give in the workflow, runs it
over a bundle path, and fails the job on any exit code other than 0.
UNCONFIRMED fails by default; an explicit input allows it for private
deployments. Neither makes any network call beyond fetching the pinned
release.

## For engineers evaluating the claims

Standard library only: `go.mod` has no `require` block and there is no
`go.sum`. A test walks the binary's import graph and fails on `net`,
`net/http`, `os/exec`, `plugin` or `unsafe`; another fails if the system
certificate store is ever consulted or `crypto/x509` imported. The
verifier makes no network calls, has no update check and no telemetry.
`events.ndjson` is read a line at a time, so memory is bounded by the
largest checkpoint window rather than by the bundle: a 1,000,000-event
bundle verifies in under 128 MiB of resident memory, which CI measures.

The public API is the `verify` package: `verify.Bundle`,
`verify.ConsistencyBundles`, `verify.ConsistencyRecorded`, and a `Report`
that marshals to `result.schema.json`. Other Sigilbase Go programs import
it instead of reimplementing hashing or proofs.

```
cmd/sigilbase-verify   the command
verify                 the public API
internal/cjson         strict JSON parser and RFC 8785 canonicaliser, with PHP's acceptance rules
internal/merkle        RFC 6962 roots, inclusion and consistency proofs
internal/tst           RFC 3161 tokens: CMS SignedData, TSTInfo, chain rules
internal/bundle        zip and directory readers, streaming line reader
internal/edsig         Ed25519 under libsodium's acceptance rules
internal/phpcompat     the PHP runtime behaviours verify.php depends on
keys                   sigilbase.json and tsa-roots.pem, embedded at build
corpus, vectors        the conformance corpus and golden vectors (mirrored, see reference/)
reference              the verify.php this code is held to agree with
tools                  the differential, mutation and fixture tools, the release build
```

The mathematics are RFC 8785 (canonical JSON), RFC 6962 (Merkle trees and
consistency proofs, verified per RFC 9162 section 2.1.4.2), Ed25519 under
libsodium's acceptance rules, and RFC 3161/5652 (timestamp tokens). Every
part names the `verify.php` function it mirrors in its comments, because
the two are held to agree and a reader chasing a difference needs to find
the other side quickly.

### Building it yourself

Releases are reproducible. With Go 1.26.5 (the toolchain `go.mod` pins),
in a clean checkout of the tag:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -ldflags "-s -w -buildid= -X github.com/sigilbase/verifier-go/verify.Version=1.6.0" \
  -o sigilbase-verify ./cmd/sigilbase-verify
```

produces the binary the release page carries for that platform, byte for
byte; `tools/build-release.sh` is the script CI runs for every platform, and
CI builds each target twice in clean checkouts and fails if the hashes
differ. `go install github.com/sigilbase/verifier-go/cmd/sigilbase-verify@latest`
builds a working verifier too (with the version stamped from the module,
not the tag), which is the route for a policy that blocks unsigned
binaries: no platform's code signing is in place yet.

### Running the tests

```bash
go vet ./... && go test -race ./...     # the suite, including the corpus and vectors

# Both verifiers over every corpus fixture; any difference fails.
# Needs PHP 8.2+ with sodium, zip and openssl for reference/verify.php.
go build -o sigilbase-verify ./cmd/sigilbase-verify
go run ./tools/differential -php php -go ./sigilbase-verify

# Seeded mutants of every passing fixture through both verifiers.
go run ./tools/mutate -php php -go ./sigilbase-verify -budget 300 -seed 1
```

Fuzz targets (`go test -fuzz`) cover the JSON parser, the DER reader, the
zip reader and the line reader, with seed corpora committed. `corpus/hostile/`
holds one fixture per parsing or acceptance rule, generated by
`go run ./tools/hostile`; CI regenerates the set and fails on any difference.

### Versions

Release numbers track the verifier's: `sigilbase-verify` 1.6.0 and
`verify.php` 1.6.0 conform to the same specification and are held to agree
on the same corpus. The corpus, vectors, keys and schema in this repository
are mirrored from the verifier repository; `reference/README.md` says how
the mirror is checked.

## Security

Verifier soundness bugs - anything that could make tampered evidence pass,
or make the two implementations disagree - are treated as critical. See
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
