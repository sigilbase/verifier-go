# Security policy

## Reporting a vulnerability

Please report verifier bugs privately, through the contact in the
[verifier repository's security policy](https://github.com/sigilbase/verifier/blob/main/SECURITY.md),
rather than opening a public issue. Include the verifier's name, version
and sha256 (every run prints them), your platform, and - if you can - a
minimal bundle or byte sequence that demonstrates the problem.

## Severity

This tool exists so that people do not have to trust Sigilbase.
Accordingly, **soundness bugs are treated as critical**: anything that could
make a tampered bundle PASS, accept a forged signature, mis-verify a Merkle
root or consistency proof, validate an RFC 3161 token that does not attest
to the checkpoint it claims to, or make `sigilbase-verify` and `verify.php`
disagree on any input. Crashes and hangs on hostile input are treated as
high severity. Cosmetic and usability issues are welcome as ordinary public
issues.

## Scope notes

The verifier makes no network calls of any kind, consults no certificate
store, and has no runtime dependencies beyond the Go standard library.
