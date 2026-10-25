# The reference implementation and the mirrored material

The [verifier repository](https://github.com/sigilbase/verifier) owns the
format specification (`FORMAT.md`), the conformance corpus (`corpus/`), the
golden vectors (`vectors/`), the trust material (`keys/`), the `--json`
schema (`result.schema.json`) and `verify.php`. This repository mirrors what
it needs of them, at the same paths, so that the Go verifier builds and
tests on its own and so that the two can be compared with a plain diff:

| Here | There |
| --- | --- |
| `corpus/` | `corpus/` |
| `vectors/` | `vectors/` |
| `keys/sigilbase.json`, `keys/receipt-keys.json`, `keys/tsa-roots.pem` | `keys/` |
| `result.schema.json` | `result.schema.json` |
| `reference/verify.php` | `verify.php` |

`reference/verify.php` is the implementation `sigilbase-verify` is held to
agree with: the differential job runs both over every corpus fixture and
the mutation job over seeded mutants, and any difference fails the build.
Its SHA-256 is in `reference/verify.php.sha256`.

The two repositories release under the same version number, and the mirror
must be exact at matching versions. `tools/check-upstream.sh <ref>` clones
the verifier repository at a tag or commit and diffs every mirrored file;
run it before tagging a release, and whenever the corpus changes upstream.

The copy here is `verify.php` 1.8.1, the verifier repository's `v1.8.1`.
