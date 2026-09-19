// Package keys carries the trust material a release ships: the Sigilbase
// signing keys and the timestamp-authority roots, embedded at build time
// from the files in this directory.
//
// verify.php, in the verifier repository, compiles the same two files into
// its TRUSTED_SIGNING_KEYS and TRUSTED_TSA_ROOTS constants, and a test in
// each implementation holds the embedded bytes to the files, so "which keys
// does this verifier trust" has exactly one answer per release. The files
// here are mirrored from that repository (see reference/README.md).
package keys

import _ "embed"

// SigilbaseJSON is keys/sigilbase.json: the signing keys, in the shape of
// the /api/v1/keys response, matched on public key bytes.
//
//go:embed sigilbase.json
var SigilbaseJSON []byte

// TSARootsPEM is keys/tsa-roots.pem: the self-signed roots of the timestamp
// authorities production anchors chain to. Text outside the PEM blocks is
// commentary and is ignored by both verifiers.
//
//go:embed tsa-roots.pem
var TSARootsPEM []byte
