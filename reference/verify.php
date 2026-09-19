<?php

declare(strict_types=1);

/**
 * Sigilbase standalone evidence verifier.
 *
 * Usage:
 *   php verify.php <bundle.zip | extracted-bundle-directory>
 *   php verify.php --skip-anchors <bundle>
 *   php verify.php --consistency <old-bundle> <new-bundle>
 *   php verify.php --consistency <bundle> --root <hex> --size <n>
 *
 * Flags:
 *   --json          one machine-readable JSON document on stdout instead of the report
 *   --quiet         no output at all; the exit code is the whole answer
 *   --print-hashes  also report the SHA-256 of this verifier file and of the
 *                   bundle file(s), so you can record exactly what ran against what
 *   --skip-anchors  skip RFC 3161 anchor validation
 *
 * Verifies a Sigilbase evidence bundle without trusting the Sigilbase
 * application or database: every event hash is recomputed from the event's
 * own fields, the hash chain is re-walked, each checkpoint's Merkle root is
 * rebuilt from the events it covers, and every checkpoint signature is
 * checked against the Ed25519 public keys listed in the manifest — with
 * each checkpoint's seal time required to fall inside its signing key's
 * active window (the manifest's created_at/retired_at per key), so a
 * retired key vouches for nothing sealed after its retirement.
 *
 * Bundles at format 1.1 may carry RFC 3161 timestamp tokens (anchors.json)
 * proving to a third party WHEN each checkpoint existed. When PHP's openssl
 * extension is present they are validated (token parses, its imprint is the
 * checkpoint hash, the CMS signature verifies, and — when a CA is provided —
 * the signer chains to it); without openssl the anchors are reported as
 * present-but-unverified, which is never a failure by itself. --skip-anchors
 * silences that.
 *
 * Bundles at format 1.2 may contain redacted events: the payload was
 * destroyed by the exporting tenant (hash-preserving redaction), every
 * hash and all metadata survive, and redactions.json declares each one.
 * A redacted event verifies through its preserved payload_hash — the
 * entry hash and the chain recompute exactly as if the payload were
 * present — and is reported plainly and counted in the summary. A payload
 * that is absent WITHOUT a matching declaration fails verification:
 * absence must be declared, never implied.
 *
 * Bundles at format 1.3 may carry informational qualified-TSA metadata on
 * anchors (provider name, jurisdiction, qualified flag, signer serial) and
 * Certificates of Evidence under certificates/, each listed in the
 * manifest with its SHA-256. The metadata is reported, never trusted: an
 * anchor's verdict rests on the token's cryptography and the provided
 * roots alone, and a claimed "qualified" status cannot rescue a token
 * that fails them. Certificates are documents about the evidence, not
 * evidence — their hashes are checked so tampering in transit is caught,
 * and a manifest-listed certificate missing from the bundle is a failure
 * (evidence with pieces deleted must never pass).
 *
 * Bundles at format 1.4 may carry the SigilSign blocks: documents.json
 * (documents by hash and metadata), signatures.json (signature records
 * with per-signer facts including the sha256 of the exact version each
 * signer viewed and signed), and links.json (document ↔ event
 * associations). They are informational-but-verifiable: every stated fact
 * is cross-checked against the events themselves — a signed version's
 * hash must match its ledgered events, each signer's viewed and signed
 * events must reference the same sha256, and every link must resolve to
 * its document.linked / document.unlinked event carrying the same hash —
 * and a contradiction fails the bundle, because metadata must never tell
 * a different story from the chain. Fields this verifier does not know,
 * including any claim about legal effect or validity, are ignored
 * entirely and can never influence the verdict.
 *
 * --consistency proves one export extends another (RFC 6962 consistency
 * over the cumulative tree of entry hashes): give it two bundles that both
 * start at sequence 1, or one such bundle plus a previously recorded root.
 *
 * This file is deliberately self-contained: no Composer, no autoloading,
 * no imports from the Sigilbase application. It needs PHP >= 8.2 with the
 * always-present hash extension and ext-sodium (ext-zip only when given a
 * .zip rather than a directory; ext-openssl only to validate RFC 3161
 * anchors, and inability to check anchors is reported, never a failure).
 * Nothing else — even the UTF-16 conversion for canonical key ordering is
 * implemented below rather than requiring mbstring. The hash and
 * canonicalisation logic intentionally duplicates the application's
 * implementation — its independence is the point.
 *
 * Results. The report separates what was proved from who proved it,
 * because they answer different questions:
 *
 *   Content integrity  the chain, payload hashes, Merkle roots and
 *                      checkpoint signatures — the bundle is internally
 *                      consistent and nothing in it has been altered
 *   Signing identity   the checkpoints were signed by a key this verifier
 *                      trusts, sealed inside that key's window
 *   Timestamps         the RFC 3161 anchors, against trust roots this
 *                      verifier carries rather than roots the bundle
 *                      supplied
 *   Scope              the range and completeness the manifest claims
 *   Redactions         every absent payload is named by an authenticated
 *                      declaration
 *
 * The distinction matters because a bundle can be perfectly self-
 * consistent and still not be Sigilbase's: anyone can produce a chain and
 * sign it with a key of their own. Internal consistency is a question
 * about the bundle; identity is a question about the world outside it,
 * and only something the verifier already knew can answer that.
 *
 * Exit codes:
 *   0 = PASS — every result that was checked holds, signing identity
 *       included
 *   1 = FAIL — content integrity, redactions or a key window failed. This
 *       includes bundles with required files missing: evidence with pieces
 *       deleted must never pass.
 *   2 = ERROR — usage, an unreadable bundle, or a manifest whose format id
 *       this verifier does not know; nothing was verified either way.
 *   3 = UNCONFIRMED — every integrity result holds, but signing identity
 *       or timestamps could not be confirmed: the maths is sound and the
 *       provenance is not established. Not a pass, and not evidence of
 *       tampering.
 *
 * Versioning: semver, distinct from the bundle format version. See
 * FORMAT.md (alongside this file) for the format specification and the
 * verifier/format compatibility table. This file makes no network calls
 * of any kind.
 */
const VERIFIER_VERSION = '1.6.0';

/**
 * How this implementation names itself in a report, beside its version and
 * the hash of the file that ran. The Go verifier reports sigilbase-verify;
 * everything else in the two reports is held equal fixture by fixture.
 */
const VERIFIER_NAME = 'verify.php';

/**
 * The signing keys this verifier trusts, compiled into the release from
 * keys/sigilbase.json by tools/compile-keys.php. A test asserts the two
 * agree, so the constant cannot drift from the file the release publishes.
 *
 * A bundle carries its own signing keys in the manifest, which is how the
 * maths gets done; it cannot establish whose keys they are. That is what
 * this set is for. Matching is by public key bytes — the id below is a
 * fingerprint anyone can recompute (the first 16 hex of the sha256 of the
 * raw public key), not a database identifier you would have to take our
 * word for.
 *
 * --keys <file> replaces this set entirely: for a private deployment, a
 * test key, or anyone who would rather fetch the keys themselves from
 * https://app.sigilbase.io/api/v1/keys and compare.
 */
const TRUSTED_SIGNING_KEYS = [
    [
        'key_id' => '120a14018fa6a5f3',
        'public_key' => '4544f991233b0f481d4a09a867de8ebc55acff4528decceb01d126a9bfe7d521',
        'algorithm' => 'ed25519',
        'created_at' => '2026-07-15T19:02:41.657979Z',
        'retired_at' => null,
    ],
];

/**
 * Timestamp-authority trust roots, compiled the same way from
 * keys/tsa-roots.pem.
 *
 * An anchor proves when a checkpoint existed only if the authority that
 * signed it is one you trust. A bundle also carries roots of its own
 * (anchors[].ca_pem), and chaining to those shows the bundle is
 * self-consistent — a bundle can carry any root it likes, including one
 * it generated. They are still used, and an anchor that validates only
 * against them makes the timestamps result unconfirmed rather than
 * passing.
 *
 * Empty until the anchoring provider's roots are pinned in a release;
 * --tsa-roots <file> supplies them meanwhile.
 */
const TRUSTED_TSA_ROOTS = 'Timestamp-authority trust roots for Sigilbase evidence anchors.

Both verifiers embed this file (tools/compile-keys.php writes it into
verify.php\'s TRUSTED_TSA_ROOTS; the Go verifier embeds it with go:embed).
An anchor token whose signer chains to one of these roots proves that the
named authority attested to the checkpoint at the token\'s genTime. A root
that appears only inside a bundle or a token never establishes trust.

Provenance, recorded 17 September 2026:

  Free TSA Root CA (www.freetsa.org)
    fetched from https://freetsa.org/files/cacert.pem
    SHA-256 A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC

  DFN-Verein Community Root CA 2022
    fingerprint published at https://doku.tid.dfn.de/doku.php?id=de:dfnpki:dfnpki_root_certs
    SHA-256 3C:DC:2C:9E:9E:5A:36:CB:58:88:FD:17:96:CB:91:2F:84:62:53:B6:82:C1:B3:20:57:53:20:33:51:0C:7B:B6

Owner confirmation of both fingerprints out of band is a release gate for
v1.6.0 (decision D3). Rotating or adding a root is a verifier release.

-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGBDCCA+ygAwIBAgIBATANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMCREUx
RTBDBgNVBAoMPFZlcmVpbiB6dXIgRm9lcmRlcnVuZyBlaW5lcyBEZXV0c2NoZW4g
Rm9yc2NodW5nc25ldHplcyBlLiBWLjEQMA4GA1UECwwHREZOLVBLSTEqMCgGA1UE
AwwhREZOLVZlcmVpbiBDb21tdW5pdHkgUm9vdCBDQSAyMDIyMB4XDTIyMDEyNjE0
MDg0MVoXDTQyMDEyMTE0MDg0MVowgZIxCzAJBgNVBAYTAkRFMUUwQwYDVQQKDDxW
ZXJlaW4genVyIEZvZXJkZXJ1bmcgZWluZXMgRGV1dHNjaGVuIEZvcnNjaHVuZ3Nu
ZXR6ZXMgZS4gVi4xEDAOBgNVBAsMB0RGTi1QS0kxKjAoBgNVBAMMIURGTi1WZXJl
aW4gQ29tbXVuaXR5IFJvb3QgQ0EgMjAyMjCCAiIwDQYJKoZIhvcNAQEBBQADggIP
ADCCAgoCggIBAMF5dV4jPdSCX8uV5h3T9HnSQzfoSK7dw0F7xqa8RvM9sqT8le/C
rrgHKx96DXtYLCiqXtRIy7Pt/5oePzJ0K6UkmvFpoW0Fg5MxDKKCE7rvWSvk9U8q
3OBYky+X5bz5+OjdLQF6LPBcNfBDrLdO+DM71/F2uDXDjwd0XCCAMTGDz2cwGbtF
447MsWdDUu3VdP9YMSYwWBi+Pj2qric6X8J6s7XTKTBnSxSNulAHtOlUjSY9Pgy/
YWkn95BUpMT/jVfeKbQrWCpCptfG7KeaM08D11VhaRIfU/LVDCQef57qdkKDh2iB
wCWvEXQMqMn18uPGgh50XCuDdlyEoKAlxWc74UQ615Q2iaLghvKCnYq5wzFOaIu9
/zLyfKURALE2c7HNY0To6CejbLRKCWF3Kkr6qZy3EtmcYxrFpEIBqJ9QYFDX4k8h
k7KIqR2/vYUFS5ZX1GLBpCqaf/YkHAUaj1iqqYc8/l5SHXquwgmQK1zhpB8zwubw
5qJWFkZGO0HeExKlJosSRWhMg471mevYVm5WjIMbF7Pl6jXeXyfGTuwbZj7D3CCk
Nyr52iviwQWHNs1KV9YOtE11H17R/H4dWXt1OuVEHkBUx4Vjde3V3rA5MivbDL/Y
XpIflBIBMzuXhbzYril4zoPnkVKONvW2JARWxUnWFJ496jroYeGg42TfAgMBAAGj
YzBhMB0GA1UdDgQWBBQQ9q+j+vYWkNDqIUESlxH4m6ValDAfBgNVHSMEGDAWgBQQ
9q+j+vYWkNDqIUESlxH4m6ValDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAS+nQQGCAkg1LphkSTZO89y5s4ORNAjc6
C9B12l3bJIvzJXZlaDzjXDGDgd/bjXrMwIprxRo/LZSSrwWcHa+HPb+RTEKRzyI4
NLUwaJUvTyxA320OugZf+x8qlyj2HHeX46M/s6ocxrU8OX+Qjf1YhkgZQH9fyMSq
CucD/BsYrDCCPATg8iU2/VaRHJ5y4ICEzAjxFDyTioKeSneTfhciYMa1COL8okEX
0T0keGx+hO9IL7UYoDdqQGpsRMQzv9OgcgJvP8CSqalE/zG84eU11awnxQHB7bz7
HV3eTVnyNg0TdFU+SMutiWa80Kf006aj5Q1Nf94kmOjN5yXe7fUniMScwaEv74oZ
hcWPJhIjLbDdwImBHB6gI5c1t4uEGZj4o0OryzVKGJeA1BvyfF2ryROG2eJN45mE
g2mIVLwy6OI/3fKxBsGzLoz/7YrnTSc4W5UtM34LZAZLVua3brTDHu2iiapiXFiE
O89xT8m1mcQJwBYH3c7j6OUwTfHKe1EpCoJNMhdRuy7HSDO39gKKI04y/pa/qzBj
2f0FlXbzD10nv8u3hBorxoEhqA3tYi3FQQwPuo6m7qOXkfPD13PRUY9/Rv/skpRY
cMJ/7jZQk6CYR7Tl9i/ipXT5B01j8HQEejv4B1ir/CqC156QweVbDbJ0Kv1rPCWC
gUikjM/huUU=
-----END CERTIFICATE-----
';

error_reporting(E_ALL);

// ---------------------------------------------------------------------------
// Output modes
// ---------------------------------------------------------------------------

$quiet = false;         // --quiet: exit code only, nothing on stdout or stderr
$jsonMode = false;      // --json: one JSON document on stdout, nothing else
$printHashes = false;   // --print-hashes: report verifier + bundle SHA-256s
$failures = [];         // every FAIL line, verbatim
$notes = [];            // every NOTE line, verbatim
$bundleHashes = [];     // path => sha256 of each bundle FILE argument (dirs are null)

const EXIT_PASS = 0;
const EXIT_FAIL = 1;
const EXIT_ERROR = 2;
const EXIT_UNCONFIRMED = 3;

const RESULT_CONTENT = 'content_integrity';
const RESULT_IDENTITY = 'signing_identity';
const RESULT_TIMESTAMPS = 'timestamps';
const RESULT_SCOPE = 'scope';
const RESULT_REDACTIONS = 'redactions';

/**
 * The five results, each pass / fail / unconfirmed / not_checked.
 *
 * Everything starts as a pass and is only ever demoted, and a demotion
 * never reverses: one failed check is enough, and a later good check does
 * not undo it.
 *
 * @var array<string, string>
 */
$results = [
    RESULT_CONTENT => 'pass',
    RESULT_IDENTITY => 'pass',
    RESULT_TIMESTAMPS => 'pass',
    RESULT_SCOPE => 'pass',
    RESULT_REDACTIONS => 'pass',
];

/** Where each key used came from: the built-in set, --keys, or the bundle alone. */
$keySources = [];

/** The signing keys trusted for this run; --keys replaces it wholesale. */
$trustedSet = TRUSTED_SIGNING_KEYS;
$trustedSetSource = 'built-in trusted set';

/** Timestamp trust roots for this run; --tsa-roots replaces them. */
$trustedTsaRoots = TRUSTED_TSA_ROOTS;
$trustedTsaRootsSource = 'built-in trusted set';

/**
 * All human-readable progress goes through here so --quiet and --json can
 * silence it wholesale.
 */
function out(string $text): void
{
    global $quiet, $jsonMode;

    if (! $quiet && ! $jsonMode) {
        fwrite(STDOUT, $text);
    }
}

/**
 * Demote one result. Ordered worst-last: nothing raises a result, so the
 * order of checks cannot change the verdict.
 */
function demote(string $result, string $state): void
{
    global $results;

    $rank = ['pass' => 0, 'not_checked' => 1, 'unconfirmed' => 2, 'fail' => 3];

    if (($rank[$state] ?? 0) > ($rank[$results[$result]] ?? 0)) {
        $results[$result] = $state;
    }
}

/**
 * The exit code the five results add up to.
 *
 * A failure anywhere is a failure. Otherwise anything unconfirmed - the
 * signing identity, the timestamps - means the maths held but the
 * provenance did not follow, which is neither a pass nor evidence of
 * tampering and needs its own answer.
 */
function verdict_code(): int
{
    global $results;

    if (in_array('fail', $results, true)) {
        return EXIT_FAIL;
    }

    return in_array('unconfirmed', $results, true) ? EXIT_UNCONFIRMED : EXIT_PASS;
}

function verdict_word(int $code): string
{
    return match ($code) {
        EXIT_PASS => 'PASS',
        EXIT_FAIL => 'FAIL',
        EXIT_UNCONFIRMED => 'UNCONFIRMED',
        default => 'ERROR',
    };
}

/**
 * A key's fingerprint: the first 16 hex of the sha256 of its raw public
 * key bytes. Anyone can recompute it from the key itself, which is the
 * point - it identifies a key without anyone having to be believed.
 */
function key_fingerprint(string $publicKeyHex): string
{
    $raw = @hex2bin($publicKeyHex);

    return $raw === false ? 'unreadable' : substr(hash('sha256', $raw), 0, 16);
}

/**
 * The trusted entry for a public key, or null when this verifier does not
 * vouch for it.
 *
 * Matched on the key bytes, never on a name or an id the bundle supplies:
 * the whole question is whether the bytes that signed the checkpoint are
 * bytes we already trusted, and anything the bundle says about itself is
 * beside the point.
 *
 * @return array{created_at: string|null, retired_at: string|null}|null
 */
function trusted_key_for(string $publicKeyHex): ?array
{
    global $trustedSet;

    foreach ($trustedSet as $entry) {
        if (! is_array($entry) || ! isset($entry['public_key']) || ! is_string($entry['public_key'])) {
            continue;
        }

        if (hash_equals(strtolower($entry['public_key']), strtolower($publicKeyHex))) {
            return [
                'created_at' => isset($entry['created_at']) && is_string($entry['created_at']) ? $entry['created_at'] : null,
                'retired_at' => isset($entry['retired_at']) && is_string($entry['retired_at']) ? $entry['retired_at'] : null,
            ];
        }
    }

    return null;
}

/**
 * Load a trusted key set from a file in the shape of the
 * /api/v1/keys response, for --keys.
 *
 * @return list<array<string, mixed>>
 */
function load_key_file(string $path): array
{
    if (! is_file($path)) {
        fail_hard("--keys file [{$path}] does not exist", EXIT_ERROR);
    }

    $decoded = json_decode((string) file_get_contents($path), true);
    $keys = is_array($decoded) ? ($decoded['keys'] ?? null) : null;

    if (! is_array($keys) || $keys === []) {
        fail_hard("--keys file [{$path}] has no \"keys\" list", EXIT_ERROR);
    }

    $loaded = [];

    foreach ($keys as $key) {
        if (! is_array($key) || ! isset($key['public_key']) || ! is_string($key['public_key'])) {
            fail_hard("--keys file [{$path}] contains an entry without a public_key", EXIT_ERROR);
        }

        $loaded[] = $key;
    }

    return $loaded;
}

/**
 * Emit the final verdict in whichever mode was requested, then exit.
 * Human-readable verdict lines are printed by the caller beforehand (they
 * differ per mode); this handles the results table, --print-hashes and
 * --json uniformly.
 *
 * @param  array<string, mixed>  $document  mode-specific fields for --json
 */
function conclude(int $code, array $document): never
{
    global $failures, $notes, $jsonMode, $quiet, $printHashes, $bundleHashes, $results, $keySources;

    $labels = [
        RESULT_CONTENT => 'Content integrity',
        RESULT_IDENTITY => 'Signing identity',
        RESULT_TIMESTAMPS => 'Timestamps',
        RESULT_SCOPE => 'Scope',
        RESULT_REDACTIONS => 'Redactions',
    ];

    out("\n");

    foreach ($labels as $key => $label) {
        out(sprintf("  %-18s %s\n", $label, strtoupper(str_replace('_', ' ', $results[$key]))));
    }

    if ($keySources !== []) {
        out("\nSigning keys used:\n");

        foreach ($keySources as $fingerprint => $source) {
            out("  {$fingerprint}  trust: {$source}\n");
        }
    }

    // Always, not only under --print-hashes: a reader needs to know which
    // verifier produced this, and comparing it with the release notes is
    // the whole point of publishing the hash.
    out("\nVerifier: v".VERIFIER_VERSION.' sha256 '.hash_file('sha256', __FILE__)."\n");

    if ($printHashes) {
        foreach ($bundleHashes as $path => $hash) {
            out('Bundle sha256:  '.($hash ?? '(directory, not hashed)')."  {$path}\n");
        }
    }

    if ($jsonMode && ! $quiet) {
        $document = [
            'verifier_name' => VERIFIER_NAME,
            'verifier_version' => VERIFIER_VERSION,
            'verifier_sha256' => hash_file('sha256', __FILE__),
            'result' => strtolower(verdict_word($code)),
            'exit_code' => $code,
            'results' => $results,
            'signing_keys' => $keySources,
            ...$document,
            'failures' => $failures,
            'notes' => $notes,
        ];

        if ($printHashes) {
            $document['bundle_sha256'] = $bundleHashes;
        }

        fwrite(STDOUT, json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
    }

    exit($code);
}

// ---------------------------------------------------------------------------
// Canonical JSON (RFC 8785 subset: integers only, used for hash preimages)
// ---------------------------------------------------------------------------

/**
 * @throws RuntimeException
 */
function canonical_encode(mixed $value): string
{
    if ($value === null) {
        return 'null';
    }

    if (is_bool($value)) {
        return $value ? 'true' : 'false';
    }

    if (is_int($value)) {
        if ($value > 9007199254740991 || $value < -9007199254740991) {
            throw new RuntimeException('integer outside the exactly representable range');
        }

        return (string) $value;
    }

    if (is_float($value)) {
        throw new RuntimeException('non-integer numbers cannot be canonicalised');
    }

    if (is_string($value)) {
        return canonical_string($value);
    }

    if ($value instanceof stdClass) {
        return canonical_object((array) $value);
    }

    if (is_array($value)) {
        if ($value === [] || array_keys($value) === range(0, count($value) - 1)) {
            return '['.implode(',', array_map('canonical_encode', $value)).']';
        }

        return canonical_object($value);
    }

    throw new RuntimeException('unsupported value type '.get_debug_type($value));
}

function canonical_string(string $value): string
{
    $out = '"';
    $length = strlen($value);
    $i = 0;

    while ($i < $length) {
        $byte = $value[$i];
        $ord = ord($byte);

        if ($byte === '"') {
            $out .= '\\"';
        } elseif ($byte === '\\') {
            $out .= '\\\\';
        } elseif ($ord === 0x08) {
            $out .= '\\b';
        } elseif ($ord === 0x09) {
            $out .= '\\t';
        } elseif ($ord === 0x0A) {
            $out .= '\\n';
        } elseif ($ord === 0x0C) {
            $out .= '\\f';
        } elseif ($ord === 0x0D) {
            $out .= '\\r';
        } elseif ($ord < 0x20) {
            $out .= sprintf('\\u%04x', $ord);
        } else {
            $out .= $byte;
        }

        $i++;
    }

    return $out.'"';
}

/**
 * UTF-8 to UTF-16BE, implemented here so this file does not require the
 * mbstring extension (RFC 8785 sorts object keys by their UTF-16 code
 * units, and auditors' PHP builds do not always include mbstring). Input
 * comes from json_decode and is therefore valid UTF-8.
 */
function utf16be(string $utf8): string
{
    $out = '';
    $i = 0;
    $length = strlen($utf8);

    while ($i < $length) {
        $byte = ord($utf8[$i]);

        if ($byte < 0x80) {
            $codepoint = $byte;
            $i += 1;
        } elseif (($byte & 0xE0) === 0xC0) {
            $codepoint = (($byte & 0x1F) << 6) | (ord($utf8[$i + 1] ?? "\x00") & 0x3F);
            $i += 2;
        } elseif (($byte & 0xF0) === 0xE0) {
            $codepoint = (($byte & 0x0F) << 12)
                | ((ord($utf8[$i + 1] ?? "\x00") & 0x3F) << 6)
                | (ord($utf8[$i + 2] ?? "\x00") & 0x3F);
            $i += 3;
        } else {
            $codepoint = (($byte & 0x07) << 18)
                | ((ord($utf8[$i + 1] ?? "\x00") & 0x3F) << 12)
                | ((ord($utf8[$i + 2] ?? "\x00") & 0x3F) << 6)
                | (ord($utf8[$i + 3] ?? "\x00") & 0x3F);
            $i += 4;
        }

        if ($codepoint > 0xFFFF) {
            // Astral plane: encode as a UTF-16 surrogate pair.
            $codepoint -= 0x10000;
            $out .= pack('n', 0xD800 | ($codepoint >> 10)).pack('n', 0xDC00 | ($codepoint & 0x3FF));
        } else {
            $out .= pack('n', $codepoint);
        }
    }

    return $out;
}

/**
 * @param  array<array-key, mixed>  $members
 */
function canonical_object(array $members): string
{
    $sortable = [];

    foreach (array_keys($members) as $originalKey) {
        $key = (string) $originalKey;
        $utf16 = utf16be($key);
        $sortable[] = [$utf16, $key, $originalKey];
    }

    usort($sortable, static fn (array $a, array $b): int => strcmp($a[0], $b[0]));

    $parts = [];

    foreach ($sortable as [, $key, $originalKey]) {
        $parts[] = canonical_string($key).':'.canonical_encode($members[$originalKey]);
    }

    return '{'.implode(',', $parts).'}';
}

// ---------------------------------------------------------------------------
// RFC 6962 Merkle tree, inclusion, and consistency
// ---------------------------------------------------------------------------

/**
 * @param  list<string>  $leaves  raw 32-byte entry hashes
 */
function merkle_root(array $leaves): string
{
    $count = count($leaves);

    if ($count === 0) {
        throw new RuntimeException('cannot build a Merkle tree with zero leaves');
    }

    if ($count === 1) {
        return hash('sha256', "\x00".$leaves[0], true);
    }

    $split = merkle_split_point($count);

    return hash(
        'sha256',
        "\x01".merkle_root(array_slice($leaves, 0, $split)).merkle_root(array_slice($leaves, $split)),
        true,
    );
}

/**
 * The Certificate Transparency hash stack: append leaves one at a time and
 * read the RFC 6962 root over everything appended so far, in memory
 * proportional to log(n) rather than to n.
 *
 * The stack holds one perfect subtree root per set bit of the leaf count,
 * sizes strictly descending, and the root folds them smallest-first.
 * Because RFC 6962 splits at the largest power of two strictly below n,
 * that fold is byte-identical to merkle_root() over the same leaves - the
 * golden vectors and the conformance corpus hold the two together.
 *
 * This is what lets a bundle of any size be verified on an ordinary
 * machine: nothing here ever holds the events.
 *
 * @param  list<array{size: int, hash: string}>  $stack
 */
function merkle_stack_append(array &$stack, string $leafData): void
{
    $stack[] = ['size' => 1, 'hash' => hash('sha256', "\x00".$leafData, true)];

    $top = count($stack) - 1;

    while ($top > 0 && $stack[$top - 1]['size'] === $stack[$top]['size']) {
        $merged = [
            'size' => $stack[$top]['size'] * 2,
            'hash' => hash('sha256', "\x01".$stack[$top - 1]['hash'].$stack[$top]['hash'], true),
        ];

        array_splice($stack, $top - 1, 2, [$merged]);
        $top--;
    }
}

/**
 * The root over every leaf appended to the stack so far, as raw bytes.
 *
 * @param  list<array{size: int, hash: string}>  $stack
 */
function merkle_stack_root(array $stack): string
{
    if ($stack === []) {
        throw new RuntimeException('cannot build a Merkle tree with zero leaves');
    }

    $hash = null;

    for ($i = count($stack) - 1; $i >= 0; $i--) {
        $hash = $hash === null
            ? $stack[$i]['hash']
            : hash('sha256', "\x01".$stack[$i]['hash'].$hash, true);
    }

    return (string) $hash;
}

function merkle_split_point(int $count): int
{
    $split = 1;

    while ($split * 2 < $count) {
        $split *= 2;
    }

    return $split;
}

/**
 * RFC 6962 section 2.1.2 consistency proof from the first $oldSize leaves
 * to the whole tree, as raw 32-byte node hashes.
 *
 * @param  list<string>  $leaves
 * @return list<string>
 */
function consistency_proof(array $leaves, int $oldSize): array
{
    $newSize = count($leaves);

    if ($oldSize < 1 || $oldSize > $newSize) {
        throw new RuntimeException('old size out of range for consistency proof');
    }

    if ($oldSize === $newSize) {
        return [];
    }

    return consistency_subproof($oldSize, $leaves, true);
}

/**
 * @param  list<string>  $leaves
 * @return list<string>
 */
function consistency_subproof(int $oldSize, array $leaves, bool $oldTreeComplete): array
{
    $count = count($leaves);

    if ($oldSize === $count) {
        return $oldTreeComplete ? [] : [merkle_root($leaves)];
    }

    $split = merkle_split_point($count);

    if ($oldSize <= $split) {
        $proof = consistency_subproof($oldSize, array_slice($leaves, 0, $split), $oldTreeComplete);
        $proof[] = merkle_root(array_slice($leaves, $split));

        return $proof;
    }

    $proof = consistency_subproof($oldSize - $split, array_slice($leaves, $split), false);
    $proof[] = merkle_root(array_slice($leaves, 0, $split));

    return $proof;
}

/**
 * RFC 9162 section 2.1.4.2 consistency verification. Roots and proof nodes
 * are raw 32-byte hashes.
 *
 * @param  list<string>  $proof
 */
function consistency_verify(int $oldSize, int $newSize, string $oldRoot, string $newRoot, array $proof): bool
{
    if ($oldSize < 1 || $newSize < $oldSize) {
        return false;
    }

    if ($oldSize === $newSize) {
        return $proof === [] && hash_equals($oldRoot, $newRoot);
    }

    if ($proof === []) {
        return false;
    }

    if (($oldSize & ($oldSize - 1)) === 0) {
        array_unshift($proof, $oldRoot);
    }

    $fn = $oldSize - 1;
    $sn = $newSize - 1;

    while (($fn & 1) === 1) {
        $fn >>= 1;
        $sn >>= 1;
    }

    $fr = array_shift($proof);
    $sr = $fr;

    foreach ($proof as $node) {
        if ($sn === 0) {
            return false;
        }

        if (($fn & 1) === 1 || $fn === $sn) {
            $fr = hash('sha256', "\x01".$node.$fr, true);
            $sr = hash('sha256', "\x01".$node.$sr, true);

            while ($fn !== 0 && ($fn & 1) === 0) {
                $fn >>= 1;
                $sn >>= 1;
            }
        } else {
            $sr = hash('sha256', "\x01".$sr.$node, true);
        }

        $fn >>= 1;
        $sn >>= 1;
    }

    return $sn === 0 && hash_equals($oldRoot, $fr) && hash_equals($newRoot, $sr);
}

// ---------------------------------------------------------------------------
// Minimal DER reader (RFC 3161 anchor tokens; used only when openssl exists)
// ---------------------------------------------------------------------------

/**
 * @return array{class: int, constructed: bool, number: int, content: string, total: int}
 */
function der_read(string $der, int $offset = 0): array
{
    $available = strlen($der) - $offset;

    if ($available < 2) {
        throw new RuntimeException('truncated DER element');
    }

    $first = ord($der[$offset]);
    $number = $first & 0x1F;

    if ($number === 0x1F) {
        throw new RuntimeException('unsupported DER tag form');
    }

    $lengthByte = ord($der[$offset + 1]);
    $headerLength = 2;

    if ($lengthByte < 0x80) {
        $contentLength = $lengthByte;
    } else {
        $lengthOfLength = $lengthByte & 0x7F;

        if ($lengthOfLength === 0 || $lengthOfLength > 4 || $available < 2 + $lengthOfLength) {
            throw new RuntimeException('unsupported or truncated DER length');
        }

        $contentLength = 0;

        for ($i = 0; $i < $lengthOfLength; $i++) {
            $contentLength = ($contentLength << 8) | ord($der[$offset + 2 + $i]);
        }

        $headerLength += $lengthOfLength;
    }

    if ($available < $headerLength + $contentLength) {
        throw new RuntimeException('truncated DER content');
    }

    return [
        'class' => $first >> 6,
        'constructed' => ($first & 0x20) !== 0,
        'number' => $number,
        'content' => substr($der, $offset + $headerLength, $contentLength),
        'total' => $headerLength + $contentLength,
    ];
}

/**
 * @return list<array{class: int, constructed: bool, number: int, content: string, total: int}>
 */
function der_children(string $content): array
{
    $children = [];
    $offset = 0;
    $length = strlen($content);

    while ($offset < $length) {
        $child = der_read($content, $offset);
        $children[] = $child;
        $offset += $child['total'];
    }

    return $children;
}

/**
 * @param  array{class: int, constructed: bool, number: int, content: string, total: int}  $element
 */
function der_reencode(array $element): string
{
    $tag = ($element['class'] << 6) | ($element['constructed'] ? 0x20 : 0x00) | $element['number'];
    $length = strlen($element['content']);

    if ($length < 0x80) {
        return chr($tag).chr($length).$element['content'];
    }

    $bytes = '';

    while ($length > 0) {
        $bytes = chr($length & 0xFF).$bytes;
        $length >>= 8;
    }

    return chr($tag).chr(0x80 | strlen($bytes)).$bytes.$element['content'];
}

function der_decode_oid(string $content): string
{
    if ($content === '') {
        throw new RuntimeException('empty OID');
    }

    $first = ord($content[0]);

    $arcs = match (true) {
        $first < 40 => [0, $first],
        $first < 80 => [1, $first - 40],
        default => [2, $first - 80],
    };

    $value = 0;

    for ($i = 1, $length = strlen($content); $i < $length; $i++) {
        $byte = ord($content[$i]);
        $value = ($value << 7) | ($byte & 0x7F);

        if (($byte & 0x80) === 0) {
            $arcs[] = $value;
            $value = 0;
        }
    }

    return implode('.', $arcs);
}

function der_decode_generalized_time(string $content): int
{
    if (preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d{1,6})?Z$/', $content, $m) !== 1) {
        throw new RuntimeException("unsupported GeneralizedTime [{$content}]");
    }

    $timestamp = gmmktime((int) $m[4], (int) $m[5], (int) $m[6], (int) $m[2], (int) $m[3], (int) $m[1]);

    if ($timestamp === false) {
        throw new RuntimeException("unparseable GeneralizedTime [{$content}]");
    }

    return $timestamp;
}

/**
 * An X.509 Time as a Unix timestamp: UTCTime (YYMMDDHHMMSSZ — two-digit
 * years 50–99 mean 1950–1999, 00–49 mean 2000–2049) or GeneralizedTime,
 * per RFC 5280 §4.1.2.5. Certificate validity fields use either.
 *
 * @param  array{class: int, constructed: bool, number: int, content: string, total: int}  $element
 */
function der_decode_time(array $element): int
{
    if ($element['class'] === 0 && $element['number'] === 0x18) {
        return der_decode_generalized_time($element['content']);
    }

    if ($element['class'] !== 0 || $element['number'] !== 0x17 || preg_match('/^(\d{2})(\d{10})Z$/', $element['content'], $m) !== 1) {
        throw new RuntimeException('unsupported X.509 Time encoding');
    }

    $century = (int) $m[1] >= 50 ? '19' : '20';

    return der_decode_generalized_time("{$century}{$m[1]}{$m[2]}Z");
}

// ---------------------------------------------------------------------------
// RFC 3161 anchor token parsing and validation
// ---------------------------------------------------------------------------

/**
 * Parse a DER TimeStampToken (CMS ContentInfo -> SignedData -> TSTInfo)
 * far enough to validate it. Throws RuntimeException on malformation.
 *
 * @return array{imprint_alg: string, imprint: string, gen_time: int, certs: list<string>, signer_issuer: string, signer_serial: string, signed_attrs_set: string, content_type_attr: string, message_digest_attr: string, digest_alg: string, sig_alg: string, signature: string, tst_info: string}
 */
function anchor_parse_token(string $der): array
{
    $contentInfo = der_read($der);
    $children = der_children($contentInfo['content']);

    if (count($children) < 2 || der_decode_oid($children[0]['content']) !== '1.2.840.113549.1.7.2') {
        throw new RuntimeException('token is not CMS SignedData');
    }

    $signedData = der_read($children[1]['content']);
    $fields = der_children($signedData['content']);

    if (count($fields) < 4) {
        throw new RuntimeException('SignedData is malformed');
    }

    $encap = der_children($fields[2]['content']);

    if ($encap === [] || der_decode_oid($encap[0]['content']) !== '1.2.840.113549.1.9.16.1.4') {
        throw new RuntimeException('eContentType is not id-ct-TSTInfo');
    }

    if (! isset($encap[1]) || $encap[1]['class'] !== 2) {
        throw new RuntimeException('SignedData carries no eContent');
    }

    $tstInfoDer = der_read($encap[1]['content'])['content'];

    $certs = [];
    $index = 3;

    while (isset($fields[$index]) && $fields[$index]['class'] === 2) {
        if ($fields[$index]['number'] === 0) {
            foreach (der_children($fields[$index]['content']) as $certificate) {
                $certs[] = der_reencode($certificate);
            }
        }

        $index++;
    }

    if (! isset($fields[$index]) || $fields[$index]['number'] !== 0x11) {
        throw new RuntimeException('SignedData has no signerInfos');
    }

    $signerInfos = der_children($fields[$index]['content']);

    if ($signerInfos === []) {
        throw new RuntimeException('signerInfos is empty');
    }

    $signer = der_children($signerInfos[0]['content']);

    if (count($signer) < 5 || $signer[1]['number'] !== 0x10 || $signer[1]['class'] !== 0) {
        throw new RuntimeException('SignerInfo sid is not issuerAndSerialNumber');
    }

    $sid = der_children($signer[1]['content']);
    $digestAlg = der_children($signer[2]['content']);

    if (count($sid) < 2 || $digestAlg === []) {
        throw new RuntimeException('SignerInfo is malformed');
    }

    if ($signer[3]['class'] !== 2 || $signer[3]['number'] !== 0) {
        throw new RuntimeException('SignerInfo has no signed attributes');
    }

    $signedAttrsContent = $signer[3]['content'];
    $contentTypeAttr = '';
    $messageDigestAttr = '';

    foreach (der_children($signedAttrsContent) as $attribute) {
        $parts = der_children($attribute['content']);

        if (count($parts) < 2) {
            continue;
        }

        $attrOid = der_decode_oid($parts[0]['content']);
        $values = der_children($parts[1]['content']);

        if ($values === []) {
            continue;
        }

        if ($attrOid === '1.2.840.113549.1.9.3') {
            $contentTypeAttr = der_decode_oid($values[0]['content']);
        }

        if ($attrOid === '1.2.840.113549.1.9.4') {
            $messageDigestAttr = $values[0]['content'];
        }
    }

    if ($contentTypeAttr === '' || $messageDigestAttr === '') {
        throw new RuntimeException('signed attributes lack contentType or messageDigest');
    }

    $sigAlg = der_children($signer[4]['content']);

    if ($sigAlg === [] || ! isset($signer[5]) || $signer[5]['number'] !== 0x04) {
        throw new RuntimeException('SignerInfo signature is malformed');
    }

    // TSTInfo: version, policy, messageImprint{alg, digest}, serial, genTime.
    $tstInfo = der_children(der_read($tstInfoDer)['content']);

    if (count($tstInfo) < 5) {
        throw new RuntimeException('TSTInfo is malformed');
    }

    $imprint = der_children($tstInfo[2]['content']);
    $imprintAlg = der_children($imprint[0]['content'] ?? '');

    if (count($imprint) < 2 || $imprintAlg === []) {
        throw new RuntimeException('TSTInfo messageImprint is malformed');
    }

    // Signature input: the signed attributes re-tagged as SET OF (RFC 5652 §5.4).
    $setLength = strlen($signedAttrsContent);
    $signedAttrsSet = $setLength < 0x80
        ? chr(0x31).chr($setLength).$signedAttrsContent
        : der_reencode(['class' => 0, 'constructed' => true, 'number' => 0x11, 'content' => $signedAttrsContent, 'total' => 0]);

    return [
        'imprint_alg' => der_decode_oid($imprintAlg[0]['content']),
        'imprint' => $imprint[1]['content'],
        'gen_time' => der_decode_generalized_time($tstInfo[4]['content']),
        'certs' => $certs,
        'signer_issuer' => der_reencode($sid[0]),
        'signer_serial' => ltrim($sid[1]['content'], "\x00"),
        'signed_attrs_set' => $signedAttrsSet,
        'content_type_attr' => $contentTypeAttr,
        'message_digest_attr' => $messageDigestAttr,
        'digest_alg' => der_decode_oid($digestAlg[0]['content']),
        'sig_alg' => der_decode_oid($sigAlg[0]['content']),
        'signature' => $signer[5]['content'],
        'tst_info' => $tstInfoDer,
    ];
}

/**
 * The pieces of a certificate's tbsCertificate that chain building and the
 * issuer checks need. validity and extensions stay as raw elements: they
 * are decoded only for certificates acting as issuers.
 *
 * @return array{serial: string, issuer: string, subject: string, validity: array{class: int, constructed: bool, number: int, content: string, total: int}, extensions: array{class: int, constructed: bool, number: int, content: string, total: int}|null}
 */
function anchor_cert_parts(string $certificateDer): array
{
    $certificate = der_read($certificateDer);
    $children = der_children($certificate['content']);

    if ($children === []) {
        throw new RuntimeException('certificate is malformed');
    }

    $tbs = der_children($children[0]['content']);
    $base = (isset($tbs[0]) && $tbs[0]['class'] === 2) ? 1 : 0;

    if (count($tbs) < $base + 6) {
        throw new RuntimeException('tbsCertificate is malformed');
    }

    $extensions = null;

    // issuerUniqueID [1], subjectUniqueID [2], extensions [3]: all optional,
    // all context-tagged, after subjectPublicKeyInfo.
    foreach (array_slice($tbs, $base + 6) as $optional) {
        if ($optional['class'] === 2 && $optional['number'] === 3) {
            $extensions = $optional;
        }
    }

    return [
        'serial' => ltrim($tbs[$base]['content'], "\x00"),
        'issuer' => der_reencode($tbs[$base + 2]),
        'subject' => der_reencode($tbs[$base + 4]),
        'validity' => $tbs[$base + 3],
        'extensions' => $extensions,
    ];
}

/**
 * The certificate's extensions as extnID => extnValue content (the DER of
 * each extension's own type). Bounded like the rest of the reader: fixed
 * nesting, no recursion.
 *
 * @param  array{class: int, constructed: bool, number: int, content: string, total: int}|null  $wrapper  the [3] EXPLICIT Extensions element, when the certificate has one
 * @return array<string, string>
 */
function anchor_cert_extensions(?array $wrapper): array
{
    if ($wrapper === null) {
        return [];
    }

    $extensions = [];

    // Extensions ::= SEQUENCE OF Extension { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    foreach (der_children(der_read($wrapper['content'])['content']) as $extension) {
        $fields = der_children($extension['content']);

        if (count($fields) < 2 || $fields[0]['number'] !== 0x06) {
            throw new RuntimeException('certificate extension is malformed');
        }

        $value = $fields[count($fields) - 1];

        if ($value['number'] !== 0x04) {
            throw new RuntimeException('certificate extension value is malformed');
        }

        $extensions[der_decode_oid($fields[0]['content'])] = $value['content'];
    }

    return $extensions;
}

/**
 * RFC 5280 §6.1.4 on a certificate acting as an issuer in the chain: it
 * must be a CA (basicConstraints cA TRUE — an absent extension counts as
 * FALSE, as the standard says), be permitted to sign certificates
 * (keyCertSign, when the keyUsage extension is present), have been valid
 * at genTime, and allow the number of intermediates beneath it when it
 * declares a pathLenConstraint. Without this, anyone holding an ordinary
 * end-entity certificate under a trusted root could issue a "timestamping"
 * signer beneath it, and every signature in the chain would verify. The
 * self-signed root is held to the same rules.
 *
 * @param  int  $intermediatesBelow  CA certificates between this issuer and the signer
 * @return list<string> failures
 */
function anchor_issuer_problems(string $issuerDer, int $genTime, int $intermediatesBelow): array
{
    try {
        $parts = anchor_cert_parts($issuerDer);
        $validity = der_children($parts['validity']['content']);

        if (count($validity) < 2) {
            throw new RuntimeException('validity is malformed');
        }

        $notBefore = der_decode_time($validity[0]);
        $notAfter = der_decode_time($validity[1]);
        $extensions = anchor_cert_extensions($parts['extensions']);
    } catch (RuntimeException) {
        return ['an issuer certificate in the chain does not parse'];
    }

    $problems = [];

    if ($genTime < $notBefore || $genTime > $notAfter) {
        $problems[] = 'an issuer certificate in the chain was not valid at genTime';
    }

    $basicConstraints = $extensions['2.5.29.19'] ?? null;

    if ($basicConstraints === null) {
        $problems[] = 'an issuer certificate in the chain is not a CA: it carries no basicConstraints extension';
    } else {
        $isCa = false;
        $pathLength = null;

        try {
            // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }
            $sequence = der_read($basicConstraints);

            if ($sequence['class'] !== 0 || $sequence['number'] !== 0x10) {
                throw new RuntimeException('basicConstraints is not a SEQUENCE');
            }

            foreach (der_children($sequence['content']) as $field) {
                if ($field['class'] !== 0) {
                    continue;
                }

                if ($field['number'] === 0x01) {
                    $isCa = strlen($field['content']) === 1 && $field['content'] !== "\x00";
                } elseif ($field['number'] === 0x02) {
                    $bytes = ltrim($field['content'], "\x00");
                    // Anything wider than four octets is beyond any chain this walk accepts.
                    $pathLength = strlen($bytes) > 4 ? PHP_INT_MAX : (int) hexdec(bin2hex($bytes === '' ? "\x00" : $bytes));
                }
            }
        } catch (RuntimeException) {
            return [...$problems, 'an issuer certificate in the chain has a malformed basicConstraints extension'];
        }

        if (! $isCa) {
            $problems[] = 'an issuer certificate in the chain is not a CA: basicConstraints cA is FALSE';
        } elseif ($pathLength !== null && $intermediatesBelow > $pathLength) {
            $problems[] = 'an issuer certificate in the chain has more intermediates beneath it than its pathLenConstraint allows';
        }
    }

    $keyUsage = $extensions['2.5.29.15'] ?? null;

    if ($keyUsage !== null && ! anchor_key_usage_permits_cert_sign($keyUsage)) {
        $problems[] = 'an issuer certificate in the chain is not permitted to sign certificates: keyUsage lacks keyCertSign';
    }

    return $problems;
}

/**
 * KeyUsage ::= BIT STRING — the first content octet counts unused trailing
 * bits; keyCertSign is bit 5 (0x04) of the first data octet.
 */
function anchor_key_usage_permits_cert_sign(string $extnValue): bool
{
    try {
        $bitString = der_read($extnValue);
    } catch (RuntimeException) {
        return false;
    }

    return $bitString['class'] === 0
        && $bitString['number'] === 0x03
        && strlen($bitString['content']) >= 2
        && (ord($bitString['content'][1]) & 0x04) !== 0;
}

function anchor_der_to_pem(string $der): string
{
    return "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n").'-----END CERTIFICATE-----';
}

/**
 * @return list<string> DER certificates in a PEM bundle string
 */
function anchor_pem_certificates(string $pem): array
{
    preg_match_all('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', $pem, $matches);

    $certificates = [];

    foreach ($matches[1] as $body) {
        $der = base64_decode((string) preg_replace('/\s+/', '', $body), true);

        if (is_string($der) && $der !== '') {
            $certificates[] = $der;
        }
    }

    return $certificates;
}

/**
 * Validate one parsed token against the message it must attest to: the
 * imprint, the messageDigest attribute, the CMS signature, the signer's
 * timestamping EKU and validity at genTime, and — when a CA is given — the
 * chain from the signer to a self-signed root inside $caPem, every issuer
 * along it being a CA (anchor_issuer_problems). Requires ext-openssl (the
 * caller checks). $caPem may be null: chain verification is then skipped
 * and reported by the caller.
 *
 * @param  array{imprint_alg: string, imprint: string, gen_time: int, certs: list<string>, signer_issuer: string, signer_serial: string, signed_attrs_set: string, content_type_attr: string, message_digest_attr: string, digest_alg: string, sig_alg: string, signature: string, tst_info: string}  $token
 * @return list<string> failures
 */
function anchor_validate(array $token, string $message, ?string $caPem): array
{
    $failures = [];

    $digests = [
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
    ];

    if (($digests[$token['imprint_alg']] ?? null) === null) {
        $failures[] = "unsupported imprint algorithm [{$token['imprint_alg']}]";
    } elseif (! hash_equals(hash($digests[$token['imprint_alg']], $message, true), $token['imprint'])) {
        $failures[] = 'the token message imprint does not match the checkpoint hash';
    }

    if ($token['content_type_attr'] !== '1.2.840.113549.1.9.16.1.4') {
        $failures[] = 'the signed contentType attribute is not id-ct-TSTInfo';
    }

    $digest = $digests[$token['digest_alg']] ?? null;

    if ($digest === null) {
        $failures[] = "unsupported digest algorithm [{$token['digest_alg']}]";

        return $failures;
    }

    if (! hash_equals(hash($digest, $token['tst_info'], true), $token['message_digest_attr'])) {
        $failures[] = 'the messageDigest attribute does not match the TSTInfo content';
    }

    // The signer certificate must be embedded (Sigilbase requests certReq).
    $signerCert = null;

    foreach ($token['certs'] as $certificateDer) {
        try {
            $parts = anchor_cert_parts($certificateDer);
        } catch (RuntimeException) {
            continue;
        }

        if ($parts['serial'] === $token['signer_serial'] && $parts['issuer'] === $token['signer_issuer']) {
            $signerCert = $certificateDer;

            break;
        }
    }

    if ($signerCert === null) {
        $failures[] = 'the signer certificate is not embedded in the token';

        return $failures;
    }

    $algorithms = [
        '1.2.840.113549.1.1.11' => OPENSSL_ALGO_SHA256,
        '1.2.840.113549.1.1.12' => OPENSSL_ALGO_SHA384,
        '1.2.840.113549.1.1.13' => OPENSSL_ALGO_SHA512,
        '1.2.840.10045.4.3.2' => OPENSSL_ALGO_SHA256,
        '1.2.840.10045.4.3.3' => OPENSSL_ALGO_SHA384,
        '1.2.840.10045.4.3.4' => OPENSSL_ALGO_SHA512,
        '1.2.840.113549.1.1.1' => [
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            'sha512' => OPENSSL_ALGO_SHA512,
        ][$digest] ?? null,
    ];

    $algorithm = $algorithms[$token['sig_alg']] ?? null;

    if ($algorithm === null) {
        $failures[] = "unsupported signature algorithm [{$token['sig_alg']}]";

        return $failures;
    }

    // The @ on openssl calls is deliberate: hostile bytes make them emit
    // warnings before returning false, and the false return already is the
    // clean failure.
    $publicKey = @openssl_pkey_get_public(anchor_der_to_pem($signerCert));

    if ($publicKey === false || @openssl_verify($token['signed_attrs_set'], $token['signature'], $publicKey, $algorithm) !== 1) {
        $failures[] = 'the CMS signature over the signed attributes does not verify';
    }

    $parsed = @openssl_x509_parse(anchor_der_to_pem($signerCert));

    if ($parsed === false) {
        $failures[] = 'the signer certificate does not parse';
    } else {
        if ($token['gen_time'] < (int) ($parsed['validFrom_time_t'] ?? 0) || $token['gen_time'] > (int) ($parsed['validTo_time_t'] ?? 0)) {
            $failures[] = 'the signer certificate was not valid at genTime';
        }

        $eku = (string) ($parsed['extensions']['extendedKeyUsage'] ?? '');

        if (! str_contains($eku, 'Time Stamping') && ! str_contains($eku, '1.3.6.1.5.5.7.3.8')) {
            $failures[] = 'the signer certificate lacks the timestamping extended key usage';
        }
    }

    if ($caPem !== null) {
        $anchors = anchor_pem_certificates($caPem);

        if ($anchors === []) {
            $failures[] = 'the provided CA chain contains no certificates';

            return $failures;
        }

        $anchorSet = array_flip(array_map('sha1', $anchors));
        $pool = [...$token['certs'], ...$anchors];
        $current = $signerCert;
        $seen = [];

        for ($depth = 0; $depth < 8; $depth++) {
            $fingerprint = sha1($current);

            if (isset($seen[$fingerprint])) {
                $failures[] = 'the certificate chain loops';

                return $failures;
            }

            $seen[$fingerprint] = true;

            try {
                $parts = anchor_cert_parts($current);
            } catch (RuntimeException) {
                $failures[] = 'a certificate in the chain does not parse';

                return $failures;
            }

            if ($parts['issuer'] === $parts['subject']) {
                if (! isset($anchorSet[$fingerprint])) {
                    $failures[] = 'the chain terminates at a root that is not in the provided CA';
                }

                return $failures;
            }

            $issuer = null;

            foreach ($pool as $candidate) {
                try {
                    if (anchor_cert_parts($candidate)['subject'] === $parts['issuer']) {
                        $issuer = $candidate;

                        break;
                    }
                } catch (RuntimeException) {
                    continue;
                }
            }

            if ($issuer === null) {
                $failures[] = 'the certificate chain is incomplete: an issuer certificate is missing';

                return $failures;
            }

            $certificate = @openssl_x509_read(anchor_der_to_pem($current));
            $issuerKey = @openssl_pkey_get_public(anchor_der_to_pem($issuer));

            if ($certificate === false || $issuerKey === false || @openssl_x509_verify($certificate, $issuerKey) !== 1) {
                $failures[] = 'a certificate signature in the chain does not verify';

                return $failures;
            }

            // Only a CA may issue. $depth intermediates already sit between
            // this issuer and the signer.
            $problems = anchor_issuer_problems($issuer, $token['gen_time'], $depth);

            if ($problems !== []) {
                return [...$failures, ...$problems];
            }

            $current = $issuer;
        }

        $failures[] = 'the certificate chain is too deep';
    }

    return $failures;
}

// ---------------------------------------------------------------------------
// Bundle loading
// ---------------------------------------------------------------------------

/**
 * @return array{dir: string, cleanup: ?string}
 */
function locate_bundle(string $argument): array
{
    if (is_dir($argument)) {
        return ['dir' => rtrim($argument, '/\\'), 'cleanup' => null];
    }

    if (! is_file($argument)) {
        fail_hard("bundle [{$argument}] does not exist", 2);
    }

    if (! class_exists(ZipArchive::class)) {
        fail_hard('the zip extension is unavailable; extract the bundle and pass the directory instead', 2);
    }

    $temp = sys_get_temp_dir().DIRECTORY_SEPARATOR.'sigilbase-verify-'.bin2hex(random_bytes(6));

    if (! mkdir($temp, 0700, true)) {
        fail_hard("could not create temp directory [{$temp}]");
    }

    $zip = new ZipArchive;

    if ($zip->open($argument) !== true) {
        fail_hard("could not open zip [{$argument}]");
    }

    if (! $zip->extractTo($temp)) {
        fail_hard("could not extract zip [{$argument}]");
    }

    $zip->close();

    return ['dir' => $temp, 'cleanup' => $temp];
}

function read_bundle_file(string $dir, string $name): string
{
    $path = $dir.DIRECTORY_SEPARATOR.$name;

    if (! is_file($path)) {
        fail_hard("bundle is missing [{$name}]");
    }

    return (string) file_get_contents($path);
}

function cleanup_bundle(?string $path): void
{
    if ($path === null) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }

    rmdir($path);
}

/**
 * Abort without a verdict-by-recomputation: exit 1 when the bundle cannot
 * pass (missing pieces are indistinguishable from deletion), exit 2 when
 * nothing was verified at all (usage/format errors).
 */
function fail_hard(string $message, int $code = 1): never
{
    global $quiet, $jsonMode;

    if ($jsonMode && ! $quiet) {
        fwrite(STDOUT, json_encode([
            'verifier_name' => VERIFIER_NAME,
            'verifier_version' => VERIFIER_VERSION,
            'result' => 'error',
            'exit_code' => $code,
            'message' => $message,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
    } elseif (! $quiet) {
        fwrite(STDERR, "FAIL: {$message}\n");
    }

    exit($code);
}

// ---------------------------------------------------------------------------
// Bundle verification
// ---------------------------------------------------------------------------

/**
 * A failed check, against the result it belongs to. Content integrity by
 * default: it is the largest category and the one a caller that forgets
 * to say should land in, because over-reporting a failure as an integrity
 * problem is the safe direction.
 */
function report(string $message, string $result = RESULT_CONTENT): void
{
    global $failures;

    $failures[] = $message;
    demote($result, 'fail');
    out("  FAIL {$message}\n");
}

/**
 * A check that could not be completed, as distinct from one that failed.
 * The maths held; something outside the bundle was missing.
 */
function unconfirmed(string $message, string $result): void
{
    global $notes;

    $notes[] = $message;
    demote($result, 'unconfirmed');
    out("  UNCONFIRMED {$message}\n");
}

function note(string $message): void
{
    global $notes;

    $notes[] = $message;
    out("  NOTE {$message}\n");
}

/**
 * A bundle value as text, for the hash comparisons and labels below.
 *
 * PHP's (string) cast is kept for scalars; an array or an object becomes ''
 * rather than 'Array' with a warning or a fatal error. No text an array or
 * object could produce is a hash, so no verdict changes, and a hostile
 * bundle can no longer stop the run before it gets one. The Go verifier
 * applies the same rule (FORMAT.md, "Parsing").
 */
function bundle_text(mixed $value): string
{
    return is_scalar($value) ? (string) $value : '';
}

/**
 * The items a bundle list yields to foreach: an array's values, an
 * object's property values, and nothing for a scalar. Those are the three
 * outcomes foreach itself has, minus the warning a scalar would raise onto
 * the output.
 *
 * @return list<mixed>
 */
function bundle_items(mixed $value): array
{
    if (is_array($value)) {
        return array_values($value);
    }

    return is_object($value) ? array_values(get_object_vars($value)) : [];
}

/**
 * PHP's (int) cast, with the warning an object would raise left out: an
 * object casts to 1, as it always has.
 */
function bundle_int(mixed $value): int
{
    return is_object($value) ? 1 : (int) $value;
}

/**
 * Parse the one timestamp shape the bundle format uses (RFC 3339, UTC,
 * microseconds); anything else is not a time this verifier will trust.
 */
function parse_rfc3339(mixed $value): ?DateTimeImmutable
{
    if (! is_string($value) || preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/', $value) !== 1) {
        return null;
    }

    try {
        return new DateTimeImmutable($value);
    } catch (Throwable) {
        // The shape check lets through values PHP's own date parser refuses
        // (a thirteenth month, a twenty-fifth hour). An unparseable time is
        // a time this verifier cannot trust, not a reason to stop the run.
        return null;
    }
}

/**
 * A trusted key vouches only for checkpoints sealed while it held
 * authority. created_at is inside the signed checkpoint preimage, so a
 * checkpoint dated after the key's retired_at (or before its created_at)
 * was either signed by a retired key or carries a forged seal time. An
 * absent window field leaves that bound unchecked (a manifest predating
 * it); a present but unparseable one fails, because it cannot be trusted.
 *
 * @param  array{created_at: mixed, retired_at: mixed}  $key
 * @return list<string>
 */
function signing_key_window_problems(array $key, string $sealedAtValue): array
{
    $sealedAt = parse_rfc3339($sealedAtValue);

    if ($sealedAt === null) {
        return ["created_at [{$sealedAtValue}] is not an RFC 3339 timestamp, so the signing key window cannot be checked"];
    }

    $problems = [];

    if ($key['created_at'] !== null) {
        $keyCreatedAt = parse_rfc3339($key['created_at']);

        if ($keyCreatedAt === null) {
            $problems[] = "the manifest's created_at for the signing key is unparseable, so the key window cannot be checked";
        } elseif ($sealedAt < $keyCreatedAt) {
            $problems[] = sprintf(
                'created_at %s is before the signing key was created (%s) — the key had no authority yet',
                $sealedAtValue,
                $key['created_at'],
            );
        }
    }

    if ($key['retired_at'] !== null) {
        $keyRetiredAt = parse_rfc3339($key['retired_at']);

        if ($keyRetiredAt === null) {
            $problems[] = "the manifest's retired_at for the signing key is unparseable, so the key window cannot be checked";
        } elseif ($sealedAt > $keyRetiredAt) {
            $problems[] = sprintf(
                "created_at %s is after the signing key's retired_at %s — a retired key signed this checkpoint",
                $sealedAtValue,
                $key['retired_at'],
            );
        }
    }

    return $problems;
}

/**
 * Does a declaration's targets block name this event?
 *
 * Targets are runs - [[2,5],[9,9]] - so a declaration covering millions of
 * events is still a short payload. A run is never expanded here: the
 * question is whether one sequence falls inside one of them.
 */
function declaration_covers(mixed $payload, string $streamId, int $sequence): bool
{
    $targets = is_object($payload) ? ($payload->targets ?? null) : null;

    if (! is_array($targets)) {
        return false;
    }

    foreach ($targets as $target) {
        if (! is_object($target) || ($target->stream ?? null) !== $streamId || ! is_array($target->runs ?? null)) {
            continue;
        }

        foreach ($target->runs as $run) {
            if (! is_array($run) || count($run) !== 2 || ! is_int($run[0]) || ! is_int($run[1])) {
                continue;
            }

            if ($sequence >= $run[0] && $sequence <= $run[1]) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Recompute one declaration's own hashes: its payload against its
 * payload_hash, and its entry hash against all of its fields.
 *
 * @return list<string> the problems found, empty when the record is sound
 */
function declaration_self_problems(stdClass $record): array
{
    $problems = [];
    $label = 'sequence '.(bundle_text($record->seq ?? '?'));

    try {
        $payloadHash = hash('sha256', canonical_encode($record->payload ?? null));

        if (! hash_equals(strtolower(bundle_text($record->payload_hash ?? '')), $payloadHash)) {
            $problems[] = "{$label}: payload_hash does not match the declaration's own payload";
        }
    } catch (RuntimeException $exception) {
        $problems[] = "{$label}: payload cannot be canonicalised ({$exception->getMessage()})";
    }

    // Exactly the preimage the events walk recomputes, including the
    // stream the declaration belongs to - which for a declaration is its
    // own stream, not the bundle's, since erasures and archived streams'
    // redactions live in the tenant's system stream.
    try {
        $preimage = canonical_encode((object) [
            'v' => 1,
            'stream' => $record->stream ?? null,
            'seq' => $record->seq ?? null,
            'occurred_at' => $record->occurred_at ?? null,
            'received_at' => $record->received_at ?? null,
            'actor' => $record->actor ?? null,
            'action' => $record->action ?? null,
            'resource' => $record->resource ?? null,
            'payload_hash' => $record->payload_hash ?? null,
            'prev' => $record->prev_hash ?? null,
        ]);

        if (! hash_equals(strtolower(bundle_text($record->entry_hash ?? '')), hash('sha256', $preimage))) {
            $problems[] = "{$label}: entry_hash does not recompute from the declaration's own fields";
        }
    } catch (RuntimeException $exception) {
        $problems[] = "{$label}: the declaration's fields cannot be canonicalised ({$exception->getMessage()}) - its entry hash cannot be recomputed";
    }

    return $problems;
}

/**
 * The redaction rule (format 1.5).
 *
 * An absent payload is accepted only against a declaration the verifier
 * can authenticate and that names this very event. redactions.json is an
 * index the exporter wrote; an index cannot be checked against anything,
 * so it informs a reader and never decides a verdict. What decides is the
 * declaration the ledger actually carries.
 *
 * Every condition below must hold, or the absence fails:
 *
 *   1. the declaration's entry hash recomputes from its own fields
 *   2. its payload matches its payload_hash
 *   3. its action matches the kind of absence, and a supplementary
 *      declaration counts only beside its authenticated original
 *   4. its targets name this stream and this sequence
 *   5. it is sealed - inside the range, by the checkpoints already
 *      verified; outside it, by an inclusion proof to a checkpoint whose
 *      signature verifies under a trusted key, inside that key's window
 *   6. if it sits in the same stream as the event, it comes after it
 *
 * @param  array<int, true>  $absentSequences
 * @param  array<int, string>  $entryHashBySequence
 */
function check_declarations(
    string $dir,
    string $format,
    string $streamId,
    int $rangeFrom,
    int $rangeTo,
    array $absentSequences,
    array $entryHashBySequence,
    array $absenceKinds,
): void {
    global $trustedSetSource;

    $count = count($absentSequences);

    out("Checking declarations for {$count} absent payload(s)...\n");

    // A bundle older than 1.5 carries no declarations at all, so an absent
    // payload in one cannot be checked against anything. Saying so plainly
    // matters: the bundle is not necessarily wrong, it is unverifiable,
    // and the fix is to export it again.
    if ($format !== 'sigilbase-evidence/1.5') {
        report(
            "this bundle is {$format} and carries {$count} absent payload(s). Formats before "
            .'sigilbase-evidence/1.5 do not carry the declarations that destroyed them, so the absences cannot be '
            .'verified. Export the range again from Sigilbase to get a bundle that can be.',
            RESULT_REDACTIONS,
        );

        out("\n");

        return;
    }

    $path = $dir.DIRECTORY_SEPARATOR.'declarations.ndjson';

    if (! is_file($path)) {
        report(
            'declarations.ndjson is missing, but payloads in this bundle are absent - '
            .'evidence with pieces deleted must never pass',
            RESULT_REDACTIONS,
        );

        out("\n");

        return;
    }

    /** @var array<string, stdClass> $authenticated  entry hash => declaration */
    $authenticated = [];

    foreach (read_lines($path) as $lineNumber => $line) {
        if (trim($line) === '') {
            continue;
        }

        $record = json_decode($line, false);

        if (! $record instanceof stdClass) {
            report('declarations.ndjson line '.($lineNumber + 1).' is not valid JSON', RESULT_REDACTIONS);

            continue;
        }

        $problems = declaration_self_problems($record);

        foreach ($problems as $problem) {
            report("declaration {$problem}", RESULT_REDACTIONS);
        }

        if ($problems === []) {
            $authenticated[strtolower(bundle_text($record->entry_hash ?? ''))] = $record;
        }
    }

    // Sealing. A declaration inside the exported range is sealed by the
    // checkpoints already rebuilt above, and its entry hash must be the
    // one the chain walked - otherwise the bundle carries two different
    // events claiming the same position. One outside the range has no
    // chain to walk, so it travels with an audit path to its checkpoint.
    $proofs = load_declaration_proofs($dir);

    foreach ($authenticated as $entryHash => $record) {
        $inThisStream = ($record->stream ?? null) === $streamId;
        $sequence = $record->seq ?? null;

        if ($inThisStream && is_int($sequence) && $sequence >= $rangeFrom && $sequence <= $rangeTo) {
            if (! isset($entryHashBySequence[$sequence]) || ! hash_equals($entryHashBySequence[$sequence], $entryHash)) {
                report(
                    "declaration at sequence {$sequence}: its entry hash is not the one events.ndjson carries at that "
                    .'sequence - the bundle contradicts itself',
                    RESULT_REDACTIONS,
                );

                unset($authenticated[$entryHash]);
            }

            continue;
        }

        $problem = declaration_proof_problem($proofs, $entryHash, $record);

        if ($problem !== null) {
            report($problem, RESULT_REDACTIONS);
            unset($authenticated[$entryHash]);
        }
    }

    // Now the rule itself, event by event.
    foreach (array_keys($absentSequences) as $sequence) {
        $kind = $absenceKinds[$sequence] ?? 'redacted';
        $wanted = $kind === 'erased' ? 'pii.subject_erased' : 'payload.redacted';
        $matched = false;

        foreach ($authenticated as $record) {
            if (! declaration_covers($record->payload ?? null, $streamId, $sequence)) {
                continue;
            }

            $action = $record->action ?? null;

            // A supplement adds targets to a statement the ledger already
            // made. On its own it is just an assertion, so it counts only
            // when its original is here and authenticated too.
            if ($action === 'declaration.supplemented') {
                $original = $record->payload->declaration->entry_hash ?? null;
                $originalRecord = is_string($original) ? ($authenticated[strtolower($original)] ?? null) : null;

                if ($originalRecord === null) {
                    report(
                        "sequence {$sequence}: a supplementary declaration names this event, but the original "
                        .'declaration it supplements is not in the bundle - a supplement proves nothing alone',
                        RESULT_REDACTIONS,
                    );

                    continue;
                }

                $action = $originalRecord->action ?? null;
            }

            if ($action !== $wanted) {
                continue;
            }

            // Same stream: the declaration records an act performed on
            // earlier events, so it cannot precede the event it destroyed.
            if (($record->stream ?? null) === $streamId && is_int($record->seq ?? null) && $record->seq <= $sequence) {
                report(
                    "sequence {$sequence}: the declaration naming it sits at sequence {$record->seq}, at or before the "
                    .'event itself - a payload cannot be declared destroyed before it existed',
                    RESULT_REDACTIONS,
                );

                continue;
            }

            $matched = true;

            break;
        }

        if (! $matched) {
            report(
                "sequence {$sequence}: the payload is absent and no authenticated {$wanted} declaration in this bundle "
                .'names it - absence must be declared, never implied',
                RESULT_REDACTIONS,
            );
        }
    }

    out("\n");
}

/**
 * Every cumulative tree size consistency.json refers to, so the events
 * walk can capture a root at each as it passes rather than slicing an
 * array of every entry hash afterwards.
 *
 * @return list<int>
 */
function consistency_tree_sizes(string $dir): array
{
    $path = $dir.DIRECTORY_SEPARATOR.'consistency.json';

    if (! is_file($path)) {
        return [];
    }

    $document = json_decode((string) file_get_contents($path), false);

    if (! is_object($document)) {
        return [];
    }

    $sizes = [];

    foreach (bundle_items($document->checkpoint_states ?? null) as $state) {
        if (is_int($state->tree_size ?? null)) {
            $sizes[] = $state->tree_size;
        }
    }

    $proof = $document->proof ?? null;

    if (is_object($proof)) {
        foreach (['from_tree_size', 'to_tree_size'] as $field) {
            if (is_int($proof->{$field} ?? null)) {
                $sizes[] = $proof->{$field};
            }
        }
    }

    return $sizes;
}

/**
 * The sequences declarations occupy inside this bundle's own range.
 *
 * Read before the events are walked so the walk knows which entry hashes
 * to keep. Everything else is discarded as it goes, which is what keeps
 * memory independent of how many events a bundle holds.
 *
 * @return array<int, true>
 */
function declaration_sequences_in_range(string $dir, string $streamId, int $rangeFrom, int $rangeTo): array
{
    $path = $dir.DIRECTORY_SEPARATOR.'declarations.ndjson';

    if (! is_file($path)) {
        return [];
    }

    $sequences = [];

    foreach (read_lines($path) as $line) {
        if (trim($line) === '') {
            continue;
        }

        $record = json_decode($line, false);

        if (! $record instanceof stdClass || ($record->stream ?? null) !== $streamId) {
            continue;
        }

        $sequence = $record->seq ?? null;

        if (is_int($sequence) && $sequence >= $rangeFrom && $sequence <= $rangeTo) {
            $sequences[$sequence] = true;
        }
    }

    return $sequences;
}

/**
 * declaration_proofs.json, indexed by the declaration entry hash it
 * proves.
 *
 * @return array<string, stdClass>
 */
function load_declaration_proofs(string $dir): array
{
    $path = $dir.DIRECTORY_SEPARATOR.'declaration_proofs.json';

    if (! is_file($path)) {
        return [];
    }

    $document = json_decode((string) file_get_contents($path), false);
    $entries = $document instanceof stdClass && is_array($document->proofs ?? null) ? $document->proofs : [];

    $indexed = [];

    foreach ($entries as $entry) {
        $entryHash = $entry->declaration->entry_hash ?? null;

        if (is_string($entryHash)) {
            $indexed[strtolower($entryHash)] = $entry;
        }
    }

    return $indexed;
}

/**
 * Is this out-of-range declaration sealed? Returns the problem, or null
 * when the audit path, the checkpoint signature and the key window all
 * hold.
 *
 * @param  array<string, stdClass>  $proofs
 */
function declaration_proof_problem(array $proofs, string $entryHash, stdClass $record): ?string
{
    $where = 'declaration '.(bundle_text($record->stream_slug ?? '?')).' sequence '.(bundle_text($record->seq ?? '?'));
    $proof = $proofs[$entryHash] ?? null;

    if ($proof === null) {
        return "{$where}: sits outside this bundle's range and carries no inclusion proof, so nothing here shows it was ever sealed";
    }

    $checkpoint = $proof->checkpoint ?? null;

    if (! $checkpoint instanceof stdClass) {
        return "{$where}: its proof carries no checkpoint";
    }

    // The audit path must rebuild the checkpoint's root from this entry.
    // Each step names its sibling and which side that sibling sits on,
    // the same RFC 6962 construction as everywhere else here: leaves are
    // prefixed 0x00 and interior nodes 0x01.
    $path = $proof->path ?? null;

    if (! is_array($path)) {
        return "{$where}: its proof is malformed";
    }

    $computed = @hex2bin($entryHash);

    if ($computed === false) {
        return "{$where}: its entry hash is not hex";
    }

    $computed = hash('sha256', "\x00".$computed, true);

    foreach ($path as $step) {
        $siblingHex = is_object($step) ? ($step->hash ?? null) : null;
        $side = is_object($step) ? ($step->side ?? null) : null;
        $siblingRaw = is_string($siblingHex) ? @hex2bin($siblingHex) : false;

        if ($siblingRaw === false || ! in_array($side, ['left', 'right'], true)) {
            return "{$where}: its audit path is malformed";
        }

        $computed = $side === 'left'
            ? hash('sha256', "\x01".$siblingRaw.$computed, true)
            : hash('sha256', "\x01".$computed.$siblingRaw, true);
    }

    if (! hash_equals(strtolower(bundle_text($checkpoint->root ?? '')), bin2hex($computed))) {
        return "{$where}: its audit path does not rebuild the checkpoint's Merkle root - the proof does not prove this declaration";
    }

    // The checkpoint itself: hash, signature, trusted key, key window.
    try {
        $preimage = canonical_encode([
            'v' => $checkpoint->v ?? 1,
            'stream' => $checkpoint->stream ?? null,
            'from' => $checkpoint->from ?? null,
            'to' => $checkpoint->to ?? null,
            'root' => $checkpoint->root ?? null,
            'prev_checkpoint' => $checkpoint->prev_checkpoint ?? null,
            'created_at' => $checkpoint->created_at ?? null,
        ]);
    } catch (RuntimeException $exception) {
        return "{$where}: its sealing checkpoint's fields cannot be canonicalised ({$exception->getMessage()}) - its hash cannot be recomputed";
    }

    $declaredHash = strtolower(bundle_text($checkpoint->checkpoint_hash ?? ''));

    if (! hash_equals($declaredHash, hash('sha256', $preimage))) {
        return "{$where}: its sealing checkpoint's hash does not recompute from its fields";
    }

    $publicKeyHex = strtolower(bundle_text($checkpoint->public_key ?? ''));
    $signature = @hex2bin(bundle_text($checkpoint->signature ?? ''));
    $message = @hex2bin($declaredHash);
    $publicKey = @hex2bin($publicKeyHex);

    $valid = is_string($signature)
        && is_string($message)
        && is_string($publicKey)
        && strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
        && strlen($publicKey) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
        && sodium_crypto_sign_verify_detached($signature, $message, $publicKey);

    if (! $valid) {
        return "{$where}: its sealing checkpoint's signature does not verify";
    }

    $trusted = trusted_key_for($publicKeyHex);

    if ($trusted === null) {
        // Not a redaction failure: the declaration is sealed, just under a
        // key whose owner this verifier cannot vouch for. The signing
        // identity result already carries that, once, for the bundle.
        return null;
    }

    foreach (signing_key_window_problems($trusted, bundle_text($checkpoint->created_at ?? '')) as $problem) {
        return "{$where}: its sealing checkpoint {$problem}";
    }

    return null;
}

/**
 * Every integer this document names under a key ending in "sequence", so
 * the SigilSign cross-checks can pull just those events out of the stream
 * rather than indexing the whole log.
 *
 * @param  array<int, true>  $into
 */
function collect_referenced_sequences(mixed $node, array &$into): void
{
    if (is_array($node)) {
        foreach ($node as $value) {
            collect_referenced_sequences($value, $into);
        }

        return;
    }

    if (! is_object($node)) {
        return;
    }

    foreach (get_object_vars($node) as $key => $value) {
        if (is_int($value) && str_ends_with($key, 'sequence')) {
            $into[$value] = true;
        }

        collect_referenced_sequences($value, $into);
    }
}

/**
 * Read a file line by line without holding it in memory.
 *
 * A full-history bundle's events.ndjson runs to gigabytes. Memory here is
 * bounded by the largest checkpoint window rather than by the size of the
 * bundle, so who can verify a bundle does not depend on how much evidence
 * it holds.
 *
 * @return Generator<int, string>
 */
function read_lines(string $path): Generator
{
    $handle = fopen($path, 'rb');

    if ($handle === false) {
        fail_hard("could not read [{$path}]");
    }

    try {
        $number = 0;

        while (($line = fgets($handle)) !== false) {
            yield $number++ => rtrim($line, "\r\n");
        }
    } finally {
        fclose($handle);
    }
}

/**
 * Fully verify one bundle. Prints progress; failures land in the global
 * list AND the returned array.
 *
 * @return array{stream_id: string, range_from: int, range_to: int, event_count: int, checkpoint_count: int, redacted_count: int, cumulative_roots: array<int, string>, leaves: list<string>, failures: list<string>}
 */
/**
 * @param  bool  $collectLeaves  keep every entry hash as raw bytes. Only
 *   --consistency needs them, because generating a consistency proof
 *   walks the whole tree; ordinary verification never holds the events.
 * @param  list<int>  $wantedRootSizes  extra cumulative tree sizes to record
 */
function verify_bundle(string $target, bool $skipAnchors, bool $collectLeaves = false, array $wantedRootSizes = []): array
{
    global $failures, $keySources, $trustedSetSource, $trustedTsaRoots, $trustedTsaRootsSource;

    $before = count($failures);

    $bundle = locate_bundle($target);
    $dir = $bundle['dir'];

    $manifest = json_decode(read_bundle_file($dir, 'manifest.json'), false);

    $format = $manifest instanceof stdClass ? ($manifest->format ?? null) : null;

    $knownFormats = [
        'sigilbase-evidence/1',
        'sigilbase-evidence/1.1',
        'sigilbase-evidence/1.2',
        'sigilbase-evidence/1.3',
        'sigilbase-evidence/1.4',
        'sigilbase-evidence/1.5',
    ];

    if (! in_array($format, $knownFormats, true)) {
        fail_hard(
            'manifest.json is missing or has an unknown format (expected one of: '.implode(', ', $knownFormats).')',
            EXIT_ERROR,
        );
    }

    $streamId = $manifest->stream->id ?? null;
    $rangeFrom = $manifest->range->from ?? null;
    $rangeTo = $manifest->range->to ?? null;

    if (! is_string($streamId) || ! is_int($rangeFrom) || ! is_int($rangeTo)) {
        fail_hard('manifest.json is missing stream id or range');
    }

    // Each trusted key carries its active window: created_at and retired_at
    // (null while active) as the manifest states them.
    $trustedKeys = [];

    foreach (bundle_items($manifest->signing_keys ?? null) as $key) {
        if (isset($key->public_key) && is_string($key->public_key)) {
            $trustedKeys[strtolower($key->public_key)] = [
                'created_at' => $key->created_at ?? null,
                'retired_at' => $key->retired_at ?? null,
            ];
        }
    }

    if ($trustedKeys === []) {
        fail_hard('manifest.json lists no signing keys');
    }

    out("Stream: {$streamId}\n");
    out("Range:  {$rangeFrom}..{$rangeTo}\n");
    out('Keys:   '.count($trustedKeys)." trusted signing key(s) in manifest\n\n");

    // ---- redactions.json (1.2, optional) -------------------------------------

    // The redactions manifest declares every event whose payload the tenant
    // destroyed. It is read before the events so the chain walk below can
    // demand a declaration for every absent payload. A missing file means
    // "no redactions declared" — absent payloads then fail.
    $redactionsBySequence = [];
    $redactionsPath = $dir.DIRECTORY_SEPARATOR.'redactions.json';

    if (is_file($redactionsPath)) {
        $redactionsDocument = json_decode((string) file_get_contents($redactionsPath), false);
        $redactionRecords = $redactionsDocument instanceof stdClass ? ($redactionsDocument->redactions ?? null) : null;

        if (! is_array($redactionRecords)) {
            report('redactions.json is present but malformed — expected a "redactions" list');
        } else {
            foreach ($redactionRecords as $record) {
                $declaredSequence = $record instanceof stdClass ? ($record->sequence ?? null) : null;

                if (! is_int($declaredSequence)) {
                    report('redactions.json contains an entry without an integer sequence');

                    continue;
                }

                if ($declaredSequence < $rangeFrom || $declaredSequence > $rangeTo) {
                    note("redactions.json declares sequence {$declaredSequence}, outside this bundle's range");

                    continue;
                }

                $redactionsBySequence[$declaredSequence] = $record;
            }
        }
    }

    // ---- checkpoints.json, read early --------------------------------------
    //
    // The ranges are needed before the events are walked, so each
    // checkpoint's Merkle root can be rebuilt as its events stream past
    // rather than from an array of every entry hash held until the end.

    $checkpointDocument = json_decode(read_bundle_file($dir, 'checkpoints.json'), false);
    $checkpoints = $checkpointDocument->checkpoints ?? null;

    if (! is_array($checkpoints) || $checkpoints === []) {
        fail_hard('checkpoints.json contains no checkpoints');
    }

    /** @var list<array{from: int, to: int}> $checkpointRanges  in file order */
    $checkpointRanges = [];

    foreach ($checkpoints as $checkpoint) {
        if (is_int($checkpoint->from ?? null) && is_int($checkpoint->to ?? null)) {
            $checkpointRanges[] = ['from' => $checkpoint->from, 'to' => $checkpoint->to];
        }
    }

    // Which entry hashes have to survive the walk: the ones declarations
    // name, so an in-range declaration can be matched to the event the
    // chain actually walked. A handful, not a million.
    $retainSequences = declaration_sequences_in_range($dir, $streamId, $rangeFrom, $rangeTo);

    // The tree sizes anything later asks about: every checkpoint boundary
    // (the consistency section records a root at each), the end of the
    // range, and whatever the caller named.
    $rootSizes = [$rangeTo => true];

    foreach ($checkpointRanges as $range) {
        $rootSizes[$range['to']] = true;
    }

    foreach ($wantedRootSizes as $size) {
        $rootSizes[$size] = true;
    }

    // consistency.json records a root at particular tree sizes; read now,
    // so the walk knows which ones to capture as it goes.
    foreach (consistency_tree_sizes($dir) as $size) {
        $rootSizes[$size] = true;
    }

    // ---- events.ndjson -----------------------------------------------------

    out("Checking events.ndjson (hash chain)...\n");

    // Streamed, one line at a time: nothing below holds more than the
    // current event, so a bundle's size does not decide who can check it.
    $eventsPath = $dir.DIRECTORY_SEPARATOR.'events.ndjson';

    if (! is_file($eventsPath)) {
        fail_hard('bundle is missing [events.ndjson]');
    }

    $events = (function () use ($eventsPath): Generator {
        foreach (read_lines($eventsPath) as $lineNumber => $line) {
            if (trim($line) === '') {
                continue;
            }

            $event = json_decode($line, false);

            if (! $event instanceof stdClass) {
                report('events.ndjson line '.($lineNumber + 1).' is not valid JSON');

                continue;
            }

            yield $event;
        }
    })();

    $eventCount = 0;
    $expectedSequence = $rangeFrom;

    // A range starting at sequence 1 must chain from the 32-zero-byte hash;
    // ranges starting later trust the first event's prev and verify onwards.
    $prevHash = $rangeFrom === 1 ? str_repeat('0', 64) : null;

    // Only the entry hashes something later actually needs, never all of
    // them: a million of them is more memory than PHP's default limit
    // allows, whatever else is done.
    $entryHashBySequence = [];
    $redactedCount = 0;
    $absentSequences = [];
    /** Which kind of destruction each absence was, from the event's own line. */
    $absenceKinds = [];

    /** @var list<array{size: int, hash: string}> $cumulativeStack */
    $cumulativeStack = [];
    /** @var list<array{size: int, hash: string}> $checkpointStack */
    $checkpointStack = [];
    /** @var array<int, string> $cumulativeRootAt  tree size => hex root */
    $cumulativeRootAt = [];
    /** @var array<int, string> $rebuiltRootFor  checkpoint first sequence => hex root */
    $rebuiltRootFor = [];
    /** @var array<int, int> $checkpointLeavesFor  checkpoint first sequence => leaves seen */
    $checkpointLeavesFor = [];
    $checkpointLeafCount = 0;
    $checkpointIndex = 0;
    /** @var list<string> $leaves  raw entry hashes, only when a caller needs them */
    $leaves = [];

    foreach ($events as $event) {
        $eventCount++;
        $sequence = $event->seq ?? null;

        if (! is_int($sequence)) {
            report('an event is missing its sequence number');

            continue;
        }

        if ($sequence !== $expectedSequence) {
            report("sequence {$sequence}: expected sequence {$expectedSequence} here — an event was deleted, inserted, or reordered");
        }

        // Payload hash: recompute from the payload content itself — except
        // for a redacted event, whose content no longer exists. Redaction
        // is only accepted when every signal agrees: payload_state says
        // "redacted", the payload is null, and — from format 1.5 — an
        // authenticated declaration in the bundle names this very event
        // (checked below, once the checkpoints that seal declarations have
        // been verified). Anything less is a failure: an absent payload is
        // never quietly acceptable.
        $payloadState = $event->payload_state ?? 'present';
        $payloadPresent = ($event->payload ?? null) !== null;
        $declaration = $redactionsBySequence[$sequence] ?? null;

        if (! in_array($payloadState, ['present', 'redacted'], true)) {
            report("sequence {$sequence}: unknown payload_state ".json_encode($payloadState));
        } elseif ($payloadState === 'redacted' || ! $payloadPresent) {
            if ($payloadPresent) {
                report("sequence {$sequence}: payload_state says redacted but a payload is present — the bundle contradicts itself");
            } elseif ($payloadState !== 'redacted') {
                report("sequence {$sequence}: payload is absent but not marked payload_state \"redacted\" — absence must be declared, never implied");
            } else {
                // Held for the declaration check. redactions.json is an
                // index, not authority: it says an absence was declared,
                // and a verifier cannot check an index against anything.
                $absentSequences[$sequence] = true;
                $redactedCount++;

                // Which ceremony destroyed it, so the declaration's action
                // can be held to it. Unknown values read as a redaction,
                // which is the stricter of the two to satisfy.
                $absence = $event->absence ?? 'redacted';
                $absenceKinds[$sequence] = $absence === 'erased' ? 'erased' : 'redacted';

                $redactedAt = is_string($declaration->redacted_at ?? null) ? substr($declaration->redacted_at, 0, 10) : 'an undeclared date';
                note("sequence {$sequence}: payload redacted {$redactedAt}, hashes preserved, chain verified from the recorded payload_hash");
            }
        } else {
            if ($declaration !== null) {
                report("sequence {$sequence}: redactions.json declares this payload redacted but it is present — the bundle contradicts itself");
            }

            try {
                $canonicalPayload = canonical_encode($event->payload ?? null);
                $payloadHash = hash('sha256', $canonicalPayload);

                if (! hash_equals(strtolower(bundle_text($event->payload_hash ?? '')), $payloadHash)) {
                    report("sequence {$sequence}: payload_hash does not match the payload content — the payload was modified");
                }
            } catch (RuntimeException $exception) {
                report("sequence {$sequence}: payload cannot be canonicalised ({$exception->getMessage()})");
            }
        }

        // Chain link: each event must reference the previous entry hash.
        if ($prevHash !== null && ($event->prev_hash ?? null) !== $prevHash) {
            report("sequence {$sequence}: prev_hash does not match the previous entry hash — the chain is broken here");
        }

        // Entry hash: recompute the v1 preimage from the event's own fields.
        try {
            $preimage = canonical_encode((object) [
                'v' => 1,
                'stream' => $streamId,
                'seq' => $sequence,
                'occurred_at' => $event->occurred_at ?? null,
                'received_at' => $event->received_at ?? null,
                'actor' => $event->actor ?? null,
                'action' => $event->action ?? null,
                'resource' => $event->resource ?? null,
                'payload_hash' => $event->payload_hash ?? null,
                'prev' => $event->prev_hash ?? null,
            ]);

            $recomputed = hash('sha256', $preimage);
        } catch (RuntimeException $exception) {
            // A float, or an integer beyond 2^53-1, in a hashed field has no
            // canonical form, so the entry hash cannot be recomputed. That is
            // a failure of the event, not a reason to stop the run.
            report("sequence {$sequence}: the event's fields cannot be canonicalised ({$exception->getMessage()}) - the entry hash cannot be recomputed");
            $recomputed = null;
        }

        if ($recomputed !== null && ! hash_equals(strtolower(bundle_text($event->entry_hash ?? '')), $recomputed)) {
            report("sequence {$sequence}: entry_hash does not recompute from the stored fields — a field was modified");
        }

        $entryHash = strtolower(bundle_text($event->entry_hash ?? ''));

        if (isset($retainSequences[$sequence])) {
            $entryHashBySequence[$sequence] = $entryHash;
        }

        // Close every checkpoint this sequence has passed, before the event
        // is counted into one. Driven by the sequence rather than by an
        // exact boundary: a deleted event means the boundary never
        // arrives, and a tree left open would fold the next checkpoint's
        // events into this one's root.
        while ($checkpointIndex < count($checkpointRanges) && $sequence > $checkpointRanges[$checkpointIndex]['to']) {
            $closingFrom = $checkpointRanges[$checkpointIndex]['from'];

            $rebuiltRootFor[$closingFrom] = $checkpointStack === []
                ? ''
                : bin2hex(merkle_stack_root($checkpointStack));
            $checkpointLeavesFor[$closingFrom] = $checkpointLeafCount;

            $checkpointStack = [];
            $checkpointLeafCount = 0;
            $checkpointIndex++;
        }

        // Both Merkle trees are fed here, as the event goes past, and
        // neither holds the events: the cumulative tree for the
        // consistency section, and a per-checkpoint tree that is finalised
        // and discarded the moment its range ends.
        $raw = @hex2bin($entryHash);

        if ($raw !== false && strlen($raw) === 32) {
            merkle_stack_append($cumulativeStack, $raw);
            merkle_stack_append($checkpointStack, $raw);
            $checkpointLeafCount++;

            if ($collectLeaves) {
                $leaves[] = $raw;
            }
        }

        // Snapshotted only at the sizes something asks about - the
        // checkpoint boundaries the consistency section records, the end
        // of the range, and any size the caller named. A root at every
        // sequence would be a million strings, which is the problem this
        // is here to avoid.
        if ($rangeFrom === 1 && $cumulativeStack !== [] && isset($rootSizes[$sequence])) {
            $cumulativeRootAt[$sequence] = bin2hex(merkle_stack_root($cumulativeStack));
        }

        $prevHash = $event->entry_hash ?? null;
        $expectedSequence = $sequence + 1;
    }

    // Close whatever is still open: the last checkpoint, and any the
    // events never reached.
    while ($checkpointIndex < count($checkpointRanges)) {
        $closingFrom = $checkpointRanges[$checkpointIndex]['from'];

        $rebuiltRootFor[$closingFrom] = $checkpointStack === []
            ? ''
            : bin2hex(merkle_stack_root($checkpointStack));
        $checkpointLeavesFor[$closingFrom] = $checkpointLeafCount;

        $checkpointStack = [];
        $checkpointLeafCount = 0;
        $checkpointIndex++;
    }

    $lastSequence = $expectedSequence - 1;

    if ($lastSequence !== $rangeTo) {
        report("events end at sequence {$lastSequence} but the manifest declares {$rangeTo} — trailing events are missing");
    }

    if ($eventCount === 0) {
        fail_hard('events.ndjson contains no events');
    }

    // ---- checkpoints.json --------------------------------------------------

    out("Checking checkpoints.json (signed Merkle checkpoints)...\n");

    $checkpointDocument = json_decode(read_bundle_file($dir, 'checkpoints.json'), false);
    $checkpoints = $checkpointDocument->checkpoints ?? null;

    if (! is_array($checkpoints) || $checkpoints === []) {
        fail_hard('checkpoints.json contains no checkpoints');
    }

    $prevCheckpointHash = $rangeFrom === 1 ? str_repeat('0', 64) : null;
    $expectedFrom = $rangeFrom;
    $checkpointHashes = [];

    foreach ($checkpoints as $checkpoint) {
        $from = $checkpoint->from ?? null;
        $to = $checkpoint->to ?? null;

        if (! is_int($from) || ! is_int($to)) {
            report('a checkpoint is missing its range');

            continue;
        }

        if ($from !== $expectedFrom) {
            report("checkpoint {$from}..{$to}: expected the range to start at {$expectedFrom} — a checkpoint is missing or reordered");
        }

        // Checkpoint hash: recompute the v1 preimage.
        try {
            $preimage = canonical_encode((object) [
                'v' => 1,
                'stream' => $streamId,
                'from' => $from,
                'to' => $to,
                'root' => $checkpoint->root ?? null,
                'prev_checkpoint' => $checkpoint->prev_checkpoint ?? null,
                'created_at' => $checkpoint->created_at ?? null,
            ]);

            $recomputedHash = hash('sha256', $preimage);
        } catch (RuntimeException $exception) {
            report("checkpoint {$from}..{$to}: the checkpoint's fields cannot be canonicalised ({$exception->getMessage()}) - the checkpoint hash cannot be recomputed");
            $recomputedHash = null;
        }

        $declaredHash = strtolower(bundle_text($checkpoint->checkpoint_hash ?? ''));

        if ($recomputedHash !== null && ! hash_equals($declaredHash, $recomputedHash)) {
            report("checkpoint {$from}..{$to}: checkpoint_hash does not recompute from its fields — the checkpoint was modified");
        }

        // Chain link between checkpoints.
        if ($prevCheckpointHash !== null && ($checkpoint->prev_checkpoint ?? null) !== $prevCheckpointHash) {
            report("checkpoint {$from}..{$to}: prev_checkpoint does not match the previous checkpoint hash — a checkpoint was removed or replaced");
        }

        // Signature: Ed25519 over the raw checkpoint hash, key must be trusted.
        $publicKeyHex = strtolower(bundle_text($checkpoint->public_key ?? ''));

        if (! isset($trustedKeys[$publicKeyHex])) {
            report("checkpoint {$from}..{$to}: signed by a key that is not in the manifest's signing keys");
        }

        // Signing identity. The signature proves that *a* key signed
        // this; only the trusted set can say whose. A bundle's own manifest
        // cannot establish that - anyone can produce a chain, sign it with
        // a key they made, and list that key in the manifest.
        $fingerprint = key_fingerprint($publicKeyHex);
        $trusted = trusted_key_for($publicKeyHex);

        if ($trusted === null) {
            $keySources[$fingerprint] = 'bundle only';

            unconfirmed(
                "checkpoint {$from}..{$to}: signed by key {$fingerprint}, which is not in the ".$trustedSetSource
                .' - the bundle is internally consistent, but nothing here establishes that Sigilbase produced it',
                RESULT_IDENTITY,
            );

            // Fall back to the window the manifest states. It is the only
            // window information available, and a bundle that contradicts
            // itself is still worth catching.
            if (isset($trustedKeys[$publicKeyHex])) {
                foreach (signing_key_window_problems($trustedKeys[$publicKeyHex], bundle_text($checkpoint->created_at ?? '')) as $problem) {
                    report("checkpoint {$from}..{$to}: {$problem}");
                }
            }
        } else {
            $keySources[$fingerprint] = $trustedSetSource;

            // The trusted set's window wins outright: the manifest's
            // created_at and retired_at are the exporter's claims about
            // its own key, and a bundle that could widen its key's window
            // could seal anything at any time.
            foreach (signing_key_window_problems($trusted, bundle_text($checkpoint->created_at ?? '')) as $problem) {
                report("checkpoint {$from}..{$to}: {$problem}", RESULT_IDENTITY);
            }
        }

        $signature = @hex2bin(bundle_text($checkpoint->signature ?? ''));
        $message = @hex2bin($declaredHash);
        $publicKey = @hex2bin($publicKeyHex);

        $signatureValid = is_string($signature)
            && is_string($message)
            && is_string($publicKey)
            && strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
            && strlen($publicKey) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            && $message !== ''
            && sodium_crypto_sign_verify_detached($signature, $message, $publicKey);

        if (! $signatureValid) {
            report("checkpoint {$from}..{$to}: the Ed25519 signature does not verify — the signature is forged or the checkpoint was modified");
        }

        // Merkle root: rebuild from the entry hashes of the covered events.
        // Rebuilt as the events streamed past, not from an array of every
        // entry hash: the root is already here, keyed by the checkpoint's
        // first sequence. The leaf count names the first missing sequence
        // when the range is short, so the message is as precise as it was
        // when the whole range sat in memory.
        $rebuiltRoot = $rebuiltRootFor[$from] ?? '';
        $received = $checkpointLeavesFor[$from] ?? 0;

        if ($received < $to - $from + 1) {
            // Short: the leaf count names the first sequence that never
            // arrived. An over-count is an insertion or a duplicate, which
            // the sequence walk above already reports at the exact event -
            // saying "missing" about it would name the wrong thing.
            report("checkpoint {$from}..{$to}: event ".($from + $received).' is missing from events.ndjson');
        } elseif (! hash_equals(strtolower(bundle_text($checkpoint->root ?? '')), $rebuiltRoot)) {
            report("checkpoint {$from}..{$to}: the Merkle root does not recompute from the events it covers");
        }

        $checkpointHashes[$declaredHash] = true;
        $prevCheckpointHash = $checkpoint->checkpoint_hash ?? null;
        $expectedFrom = $to + 1;
    }

    $lastCovered = $expectedFrom - 1;

    if ($lastCovered !== $rangeTo) {
        report("checkpoints cover up to sequence {$lastCovered} but the manifest declares {$rangeTo}", RESULT_SCOPE);
    }

    // ---- declarations.ndjson / declaration_proofs.json (1.5) ----------------

    if ($absentSequences !== []) {
        check_declarations($dir, (string) $format, $streamId, $rangeFrom, $rangeTo, $absentSequences, $entryHashBySequence, $absenceKinds);
    } else {
        out("No payload in this bundle is absent; nothing to declare.\n\n");
    }

    // ---- anchors.json (format 1.1, optional) --------------------------------

    $anchorsPath = $dir.DIRECTORY_SEPARATOR.'anchors.json';

    if (! is_file($anchorsPath)) {
        // No anchors at all: nothing was checked, which is not the same as
        // checked and sound.
        demote(RESULT_TIMESTAMPS, 'not_checked');
    } else {
        $anchorDocument = json_decode((string) file_get_contents($anchorsPath), false);
        $anchors = is_object($anchorDocument) && is_array($anchorDocument->anchors ?? null) ? $anchorDocument->anchors : [];

        if ($anchors !== [] && $skipAnchors) {
            out('Skipping '.count($anchors)." RFC 3161 anchor token(s) (--skip-anchors).\n");
            demote(RESULT_TIMESTAMPS, 'not_checked');
        } elseif ($anchors === []) {
            demote(RESULT_TIMESTAMPS, 'not_checked');
        } elseif (! extension_loaded('openssl')) {
            out("Checking anchors.json (RFC 3161 timestamps)...\n");
            note('anchors present, not verified (the openssl extension is unavailable); use --skip-anchors to silence');
            demote(RESULT_TIMESTAMPS, 'not_checked');
        } else {
            out("Checking anchors.json (RFC 3161 timestamps)...\n");

            foreach ($anchors as $index => $anchor) {
                $label = 'anchor #'.($index + 1).' ('.(bundle_text($anchor->provider ?? 'unknown')).')';
                $checkpointHash = strtolower(bundle_text($anchor->checkpoint_hash ?? ''));

                if (! isset($checkpointHashes[$checkpointHash])) {
                    report("{$label}: anchors a checkpoint hash that is not in this bundle");

                    continue;
                }

                $tokenDer = base64_decode(bundle_text($anchor->token ?? ''), true);

                if (! is_string($tokenDer) || $tokenDer === '') {
                    report("{$label}: the token is not valid base64");

                    continue;
                }

                if (! hash_equals(strtolower(bundle_text($anchor->token_hash ?? '')), hash('sha256', $tokenDer))) {
                    report("{$label}: the token does not match its recorded token_hash");

                    continue;
                }

                try {
                    $token = anchor_parse_token($tokenDer);
                } catch (RuntimeException $exception) {
                    report("{$label}: the token does not parse ({$exception->getMessage()})");

                    continue;
                }

                // Trust roots come from this verifier, never from the
                // bundle alone. A bundle can carry any root it likes,
                // including one it generated, so chaining to a
                // bundle-supplied root shows the exporter is internally
                // consistent and nothing more.
                $bundlePem = isset($anchor->ca_pem) && is_string($anchor->ca_pem) && $anchor->ca_pem !== '' ? $anchor->ca_pem : null;
                $trustedPem = $trustedTsaRoots !== '' ? $trustedTsaRoots : null;
                $caPem = $trustedPem ?? $bundlePem;

                foreach (anchor_validate($token, (string) hex2bin($checkpointHash), $caPem) as $problem) {
                    report("{$label}: {$problem}", RESULT_TIMESTAMPS);
                }

                if ($trustedPem === null && $bundlePem !== null) {
                    unconfirmed(
                        "{$label}: the token and its imprint verify, and the signer chains only to a root this bundle "
                        .'supplied - which shows the bundle is self-consistent, not that a timestamp authority you '
                        .'trust issued it. Pass --tsa-roots with the authority\'s own roots to settle it',
                        RESULT_TIMESTAMPS,
                    );
                } elseif ($caPem === null) {
                    unconfirmed(
                        "{$label}: the token and its imprint verify, but no trust roots were available, so the "
                        .'timestamp authority\'s identity was not established',
                        RESULT_TIMESTAMPS,
                    );
                }

                // Informational qualified-TSA metadata (format 1.3). Reported
                // as-is and deliberately kept OUT of the verdict: the exporter
                // wrote these fields, and a claimed status is not evidence —
                // only the token's cryptography above is.
                if (($anchor->qualified ?? null) === true) {
                    $providerName = is_string($anchor->provider_name ?? null) ? $anchor->provider_name : bundle_text($anchor->provider ?? 'unknown');
                    $jurisdiction = is_string($anchor->jurisdiction ?? null) ? " ({$anchor->jurisdiction})" : '';

                    note("{$label}: the exporter recorded this token as issued by a qualified trust service provider — {$providerName}{$jurisdiction}. Informational: the verdict rests on the cryptographic checks alone");
                }
            }
        }
    }

    // ---- certificates/ (format 1.3, optional, informational) -----------------

    $certificateRecords = is_array($manifest->certificates ?? null) ? $manifest->certificates : [];

    if ($certificateRecords !== []) {
        out('Checking '.count($certificateRecords)." Certificate(s) of Evidence (certificates/)...\n");

        foreach ($certificateRecords as $index => $record) {
            $recordId = is_string($record->id ?? null) ? $record->id : ('#'.($index + 1));
            $label = "certificate {$recordId}";

            $file = is_string($record->file ?? null) ? $record->file : null;

            if ($file === null || ! str_starts_with($file, 'certificates/') || str_contains($file, '..')) {
                report("{$label}: the manifest entry has a missing or unsafe file path");

                continue;
            }

            $path = $dir.DIRECTORY_SEPARATOR.str_replace('/', DIRECTORY_SEPARATOR, $file);

            if (! is_file($path)) {
                report("{$label}: listed in the manifest but missing from the bundle");

                continue;
            }

            if (! hash_equals(strtolower(bundle_text($record->sha256 ?? '')), (string) hash_file('sha256', $path))) {
                report("{$label}: the file does not match its manifest sha256");
            }
        }

        note(count($certificateRecords).' Certificate(s) of Evidence travelled with this bundle. They are documents about the evidence; the cryptographic verification above does not depend on them');
    }

    // ---- documents.json / signatures.json / links.json (format 1.4, optional) -

    // The SigilSign blocks: documents by hash, signature records, and
    // document ↔ event links. Informational-but-verifiable: every stated
    // fact is cross-checked against the events themselves, and a
    // contradiction FAILS the bundle — metadata must never be able to
    // tell a different story from the chain. Fields this verifier does
    // not know — including any claim about legal effect or validity —
    // are ignored entirely and can never influence the verdict. A
    // redacted event's facts cannot be cross-checked and are noted, not
    // failed: redaction is a declared destruction, not a contradiction.

    // A second streaming pass rather than an index of every event: the
    // point of reading events.ndjson a line at a time is not to hold it.
    // Only the events these blocks actually reference are kept - those
    // carrying a signing: resource, and those at a sequence one of the
    // blocks names.
    $eventBySequence = [];
    $eventsBySigningResource = [];

    $sigilSignPaths = array_filter(
        ['documents.json', 'signatures.json', 'links.json'],
        static fn (string $name): bool => is_file($dir.DIRECTORY_SEPARATOR.$name),
    );

    if ($sigilSignPaths !== []) {
        $wantedSequences = [];

        foreach ($sigilSignPaths as $name) {
            collect_referenced_sequences(
                json_decode((string) file_get_contents($dir.DIRECTORY_SEPARATOR.$name), false),
                $wantedSequences,
            );
        }

        foreach (read_lines($eventsPath) as $line) {
            if (trim($line) === '') {
                continue;
            }

            $event = json_decode($line, false);

            if (! $event instanceof stdClass) {
                continue;
            }

            $eventResource = $event->resource ?? null;
            $isSigning = is_string($eventResource) && str_starts_with($eventResource, 'signing:');

            $sequenceKey = $event->seq ?? -1;

            if (is_array($sequenceKey) || is_object($sequenceKey)) {
                $sequenceKey = -1;
            }

            if (! $isSigning && ! isset($wantedSequences[$sequenceKey])) {
                continue;
            }

            if (is_int($event->seq ?? null)) {
                $eventBySequence[$event->seq] = $event;
            }

            if ($isSigning) {
                $eventsBySigningResource[$eventResource][] = $event;
            }
        }
    }

    $documentsPath = $dir.DIRECTORY_SEPARATOR.'documents.json';

    if (is_file($documentsPath)) {
        out("Checking documents.json (document hashes against the chain)...\n");

        $documentsDocument = json_decode((string) file_get_contents($documentsPath), false);
        $documentRecords = $documentsDocument instanceof stdClass ? ($documentsDocument->documents ?? null) : null;

        if (! is_array($documentRecords)) {
            report('documents.json is present but malformed — expected a "documents" list');
        } else {
            $checkedVersions = 0;

            foreach ($documentRecords as $record) {
                $slug = is_string($record->slug ?? null) ? $record->slug : '(unnamed)';

                foreach ((array) ($record->versions ?? []) as $versionRecord) {
                    $sequence = $versionRecord->published_sequence ?? null;
                    $statedSha = strtolower(bundle_text($versionRecord->sha256 ?? ''));

                    if (! is_int($sequence)) {
                        report("documents.json: document {$slug} lists a version without an integer published_sequence");

                        continue;
                    }

                    $publishedEvent = $eventBySequence[$sequence] ?? null;

                    if ($publishedEvent === null) {
                        report("documents.json: document {$slug} points at sequence {$sequence}, which is not in this bundle");

                        continue;
                    }

                    if (($publishedEvent->action ?? null) !== 'document.published') {
                        report("documents.json: document {$slug} points at sequence {$sequence}, which is not a document.published event");

                        continue;
                    }

                    if (! is_object($publishedEvent->payload ?? null)) {
                        note("documents.json: document {$slug}'s publication at sequence {$sequence} has a redacted payload; the stated hash cannot be cross-checked");

                        continue;
                    }

                    $ledgeredSha = strtolower(bundle_text($publishedEvent->payload->sha256 ?? ''));

                    if (! hash_equals($ledgeredSha, $statedSha)) {
                        report("documents.json: document {$slug} states sha256 {$statedSha} but its document.published event at sequence {$sequence} carries {$ledgeredSha}");

                        continue;
                    }

                    $checkedVersions++;
                }
            }

            note("documents.json: {$checkedVersions} document version hash(es) match their ledgered document.published events");
        }
    }

    $signaturesPath = $dir.DIRECTORY_SEPARATOR.'signatures.json';

    if (is_file($signaturesPath)) {
        out("Checking signatures.json (signature records against the chain)...\n");

        $signaturesDocument = json_decode((string) file_get_contents($signaturesPath), false);
        $signatureRecords = $signaturesDocument instanceof stdClass ? ($signaturesDocument->signatures ?? null) : null;

        if (! is_array($signatureRecords)) {
            report('signatures.json is present but malformed — expected a "signatures" list');
        } else {
            $checkedSignatures = 0;

            foreach ($signatureRecords as $record) {
                $signingId = is_string($record->id ?? null) ? $record->id : null;

                if ($signingId === null) {
                    report('signatures.json contains a record without an id');

                    continue;
                }

                $label = "signatures.json: signing {$signingId}";
                $documentSha = strtolower(bundle_text($record->document->sha256 ?? ''));
                $signingEvents = $eventsBySigningResource['signing:'.$signingId] ?? [];

                if ($signingEvents === []) {
                    report("{$label} has no events in this bundle — a stated signing must exist in the chain");

                    continue;
                }

                // The chain's own story: what each signer saw and signed.
                $viewedShaByEmail = [];
                $signedByEmail = [];

                foreach ($signingEvents as $signingEvent) {
                    $payload = is_object($signingEvent->payload ?? null) ? $signingEvent->payload : null;

                    if ($payload === null) {
                        continue; // redacted: declared destruction, noted globally below
                    }

                    $email = is_string($payload->signer->email ?? null) ? strtolower($payload->signer->email) : null;

                    if ($email === null) {
                        continue;
                    }

                    if (($signingEvent->action ?? null) === 'signature.viewed') {
                        $viewedShaByEmail[$email] = strtolower(bundle_text($payload->sha256 ?? ''));
                    }

                    if (($signingEvent->action ?? null) === 'signature.signed') {
                        $signedByEmail[$email] = $payload;
                    }
                }

                foreach ($signedByEmail as $email => $payload) {
                    $signedSha = strtolower(bundle_text($payload->sha256 ?? ''));

                    // The load-bearing check: the signed hash is the
                    // document's hash, and it is the hash the same signer
                    // viewed.
                    if ($documentSha !== '' && ! hash_equals($signedSha, $documentSha)) {
                        report("{$label}: the record states document sha256 {$documentSha} but signer {$email}'s signature.signed event carries {$signedSha}");
                    }

                    if (isset($viewedShaByEmail[$email]) && ! hash_equals($viewedShaByEmail[$email], $signedSha)) {
                        report("{$label}: signer {$email} viewed sha256 {$viewedShaByEmail[$email]} but signed {$signedSha} — the viewed and signed versions must be the same");
                    }
                }

                // Every signer the record claims signed must have a
                // matching event, with the mark hash agreeing when stated.
                foreach ((array) ($record->signers ?? []) as $signerRecord) {
                    if (($signerRecord->status ?? null) !== 'signed') {
                        continue;
                    }

                    $email = is_string($signerRecord->email ?? null) ? strtolower($signerRecord->email) : '';
                    $payload = $signedByEmail[$email] ?? null;

                    if ($payload === null) {
                        report("{$label}: the record claims {$email} signed but no signature.signed event in this bundle records it");

                        continue;
                    }

                    $statedMark = strtolower(bundle_text($signerRecord->signature_sha256 ?? ''));
                    $ledgeredMark = strtolower(bundle_text($payload->signature_sha256 ?? ''));

                    if ($statedMark !== '' && $ledgeredMark !== '' && ! hash_equals($ledgeredMark, $statedMark)) {
                        report("{$label}: {$email}'s stated signature-mark hash does not match the ledgered event");
                    }

                    $checkedSignatures++;
                }
            }

            note("signatures.json: {$checkedSignatures} signature(s) verified against their ledgered events — viewed and signed hashes agree");
            note('signatures.json is informational metadata: its facts are cross-checked against the chain above, and everything else in it — including any claim about legal effect or validity — is ignored and cannot influence the verdict');
        }
    }

    $linksPath = $dir.DIRECTORY_SEPARATOR.'links.json';

    if (is_file($linksPath)) {
        out("Checking links.json (document ↔ event links against the chain)...\n");

        $linksDocument = json_decode((string) file_get_contents($linksPath), false);
        $linkRecords = $linksDocument instanceof stdClass ? ($linksDocument->links ?? null) : null;

        if (! is_array($linkRecords)) {
            report('links.json is present but malformed — expected a "links" list');
        } else {
            $resolvedLinks = 0;

            foreach ($linkRecords as $index => $linkRecord) {
                $linkLabel = 'links.json entry #'.($index + 1);
                $linkSha = strtolower(bundle_text($linkRecord->sha256 ?? ''));
                $resolved = true;

                foreach (['linked_sequence' => 'document.linked', 'unlinked_sequence' => 'document.unlinked'] as $field => $expectedAction) {
                    $sequence = $linkRecord->{$field} ?? null;

                    if ($sequence === null) {
                        if ($field === 'linked_sequence') {
                            report("{$linkLabel} has no linked_sequence — a link must point at its ledgered fact");
                            $resolved = false;
                        }

                        continue;
                    }

                    $linkEvent = is_int($sequence) ? ($eventBySequence[$sequence] ?? null) : null;

                    if ($linkEvent === null || ($linkEvent->action ?? null) !== $expectedAction) {
                        report("{$linkLabel}: {$field} ".bundle_text($sequence)." does not resolve to a {$expectedAction} event in this bundle");
                        $resolved = false;

                        continue;
                    }

                    if (! is_object($linkEvent->payload ?? null)) {
                        note("{$linkLabel}: the {$expectedAction} event at sequence {$sequence} has a redacted payload; its hash cannot be cross-checked");

                        continue;
                    }

                    $eventSha = strtolower(bundle_text($linkEvent->payload->sha256 ?? ''));

                    if ($linkSha !== '' && ! hash_equals($eventSha, $linkSha)) {
                        report("{$linkLabel}: states sha256 {$linkSha} but the {$expectedAction} event at sequence {$sequence} carries {$eventSha}");
                        $resolved = false;
                    }
                }

                if ($resolved) {
                    $resolvedLinks++;
                }
            }

            note("links.json: {$resolvedLinks} link fact(s) resolve to their ledgered document.linked/document.unlinked events with matching hashes");
            note('a link records that the exporting tenant associated a document with these events at a provable time; it asserts nothing about legal effect, which this verifier neither checks nor reports');
        }
    }

    // ---- consistency.json (format 1.1, optional) -----------------------------

    $consistencyPath = $dir.DIRECTORY_SEPARATOR.'consistency.json';

    if (is_file($consistencyPath) && $rangeFrom === 1) {
        out("Checking consistency.json (cumulative tree states)...\n");

        $consistency = json_decode((string) file_get_contents($consistencyPath), false);

        // The roots were captured as the events streamed past, at exactly
        // the sizes this file refers to.
        $rootAt = static fn (int $size): ?string => $cumulativeRootAt[$size] ?? null;

        if ($rootAt($rangeTo) !== null && is_object($consistency)) {
            $declaredRoot = strtolower(bundle_text($consistency->root ?? ''));

            if (! hash_equals($declaredRoot, (string) $rootAt($rangeTo))) {
                report('consistency.json: the cumulative root does not recompute from the events');
            }

            foreach (bundle_items($consistency->checkpoint_states ?? null) as $state) {
                $size = $state->tree_size ?? null;

                if (! is_int($size) || $size < 1 || $size > $rangeTo) {
                    report('consistency.json: a checkpoint state has an invalid tree_size');

                    continue;
                }

                $stateRoot = $rootAt($size);

                if ($stateRoot === null || ! hash_equals(strtolower(bundle_text($state->root ?? '')), $stateRoot)) {
                    report("consistency.json: the recorded root for tree_size {$size} does not recompute");
                }
            }

            $proof = $consistency->proof ?? null;

            if (is_object($proof)) {
                $nodes = [];

                foreach ((array) ($proof->nodes ?? []) as $hex) {
                    $node = is_string($hex) ? @hex2bin($hex) : false;

                    if (is_string($node)) {
                        $nodes[] = $node;
                    }
                }

                $fromSize = bundle_int($proof->from_tree_size ?? 0);
                $toSize = bundle_int($proof->to_tree_size ?? 0);

                $fromRoot = $rootAt($fromSize);
                $toRoot = $rootAt($rangeTo);

                $valid = $fromSize >= 1
                    && $toSize === $rangeTo
                    && $fromRoot !== null
                    && $toRoot !== null
                    && consistency_verify(
                        $fromSize,
                        $toSize,
                        (string) hex2bin($fromRoot),
                        (string) hex2bin($toRoot),
                        $nodes,
                    );

                if (! $valid) {
                    report('consistency.json: the recorded consistency proof does not verify');
                }
            }
        }
    }

    cleanup_bundle($bundle['cleanup']);

    return [
        'stream_id' => $streamId,
        'range_from' => $rangeFrom,
        'range_to' => $rangeTo,
        'event_count' => $eventCount,
        'checkpoint_count' => count($checkpoints),
        'redacted_count' => $redactedCount,
        // Cumulative RFC 6962 roots, captured as the events streamed past,
        // at the sizes something asks about. Not one per event: that would
        // be the memory this streaming exists to avoid.
        'cumulative_roots' => $cumulativeRootAt,
        // Raw entry hashes, only when the caller asked for them, because
        // generating a consistency proof walks the whole tree.
        'leaves' => $leaves,
        'failures' => array_slice($failures, $before),
    ];
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

// When this file is require()d — by the test suite, or by anyone wanting
// the canonicalisation/Merkle functions as a library — stop here.
// Everything above is functions; everything below is the CLI.
if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) {
    return;
}

$arguments = array_slice($argv, 1);
$skipAnchors = false;
$consistencyMode = false;
$recordedRoot = null;
$recordedSize = null;
$keysFile = null;
$tsaRootsFile = null;
$showHelp = false;
$targets = [];

for ($i = 0; $i < count($arguments); $i++) {
    $argument = $arguments[$i];

    if ($argument === '--skip-anchors') {
        $skipAnchors = true;
    } elseif ($argument === '--consistency') {
        $consistencyMode = true;
    } elseif ($argument === '--json') {
        $jsonMode = true;
    } elseif ($argument === '--quiet') {
        $quiet = true;
    } elseif ($argument === '--print-hashes') {
        $printHashes = true;
    } elseif ($argument === '--root') {
        $recordedRoot = strtolower((string) ($arguments[++$i] ?? ''));
    } elseif (str_starts_with($argument, '--root=')) {
        $recordedRoot = strtolower(substr($argument, 7));
    } elseif ($argument === '--size') {
        $recordedSize = (int) ($arguments[++$i] ?? 0);
    } elseif (str_starts_with($argument, '--size=')) {
        $recordedSize = (int) substr($argument, 7);
    } elseif ($argument === '--keys') {
        $keysFile = (string) ($arguments[++$i] ?? '');
    } elseif (str_starts_with($argument, '--keys=')) {
        $keysFile = substr($argument, 7);
    } elseif ($argument === '--tsa-roots') {
        $tsaRootsFile = (string) ($arguments[++$i] ?? '');
    } elseif (str_starts_with($argument, '--tsa-roots=')) {
        $tsaRootsFile = substr($argument, 12);
    } elseif ($argument === '--help' || $argument === '-h') {
        $showHelp = true;
    } elseif (str_starts_with($argument, '--')) {
        fail_hard("unknown option [{$argument}]", EXIT_ERROR);
    } else {
        $targets[] = $argument;
    }
}

$usage = <<<'USAGE'
Sigilbase evidence verifier.

usage: php verify.php [options] <bundle.zip | extracted-bundle-directory>
       php verify.php --consistency <old-bundle> <new-bundle>
       php verify.php --consistency <bundle> --root <hex> --size <n>

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

USAGE;

if ($showHelp) {
    fwrite(STDOUT, $usage);

    exit(EXIT_PASS);
}

// --keys and --tsa-roots replace the compiled-in sets wholesale, and say
// so in the report: "which keys did this run actually trust" must never
// be something a reader has to guess.
if ($keysFile !== null) {
    $trustedSet = load_key_file($keysFile);
    $trustedSetSource = "--keys {$keysFile}";
}

if ($tsaRootsFile !== null) {
    if (! is_file($tsaRootsFile)) {
        fail_hard("--tsa-roots file [{$tsaRootsFile}] does not exist", EXIT_ERROR);
    }

    $trustedTsaRoots = (string) file_get_contents($tsaRootsFile);
    $trustedTsaRootsSource = "--tsa-roots {$tsaRootsFile}";
}

foreach ($targets as $target) {
    $bundleHashes[$target] = is_file($target) ? hash_file('sha256', $target) : null;
}

out('Sigilbase evidence verifier v'.VERIFIER_VERSION."\n");

if (! $consistencyMode) {
    if (count($targets) !== 1) {
        if (! $quiet && ! $jsonMode) {
            fwrite(STDERR, $usage);
        }

        fail_hard('expected exactly one bundle argument', EXIT_ERROR);
    }

    out("Bundle: {$targets[0]}\n\n");

    $result = verify_bundle($targets[0], $skipAnchors);

    out("\n");

    $consistencyState = null;
    $code = verdict_code();

    if ($code === EXIT_FAIL) {
        out('FAIL: '.count($failures)." problem(s) found. This bundle does NOT verify.\n");
    } else {
        out("{$result['event_count']} events and {$result['checkpoint_count']} checkpoints verified for stream {$result['stream_id']} ({$result['range_from']}..{$result['range_to']}).\n");
        out("No event has been modified, deleted, or reordered, and every checkpoint signature is genuine.\n");

        if ($result['redacted_count'] > 0) {
            out("Redactions: {$result['redacted_count']} payload(s) were destroyed by the tenant, each named by an authenticated declaration in this bundle; their hashes are preserved and the chain is intact.\n");
        }

        if ($code === EXIT_UNCONFIRMED) {
            out("\nUNCONFIRMED: the maths holds and nothing here has been altered, but this bundle's\n");
            out("origin is not established - see the results above. It is not evidence of tampering,\n");
            out("and it is not a pass.\n");
        } else {
            out("\nPASS: every result that was checked holds.\n");
        }

        $cumulativeRoot = $result['cumulative_roots'][$result['range_to']] ?? null;

        if ($result['range_from'] === 1 && $cumulativeRoot !== null) {
            $consistencyState = ['tree_size' => $result['range_to'], 'root' => $cumulativeRoot];

            out("\nConsistency state: tree_size={$consistencyState['tree_size']} root={$consistencyState['root']}\n");
            out("Record these two values: a future export can prove it extends this one (--consistency).\n");
        }
    }

    conclude($code, [
        'mode' => 'verify',
        'bundle' => [
            'path' => $targets[0],
            'stream' => $result['stream_id'],
            'range' => ['from' => $result['range_from'], 'to' => $result['range_to']],
            'events' => $result['event_count'],
            'checkpoints' => $result['checkpoint_count'],
            'redacted_events' => $result['redacted_count'],
        ],
        'consistency_state' => $consistencyState,
    ]);
}

// ---- consistency mode -------------------------------------------------------

if (count($targets) === 2 && $recordedRoot === null && $recordedSize === null) {
    out("Mode:   consistency between two bundles\n\n");
    out("=== Old bundle: {$targets[0]} ===\n\n");

    // Generating a consistency proof walks the whole tree, so this mode
    // asks for the leaves. Ordinary verification never does.
    $old = verify_bundle($targets[0], $skipAnchors, collectLeaves: true);

    out("\n=== New bundle: {$targets[1]} ===\n\n");

    $new = verify_bundle($targets[1], $skipAnchors, collectLeaves: true);

    out("\nChecking consistency (RFC 6962)...\n");

    if ($old['stream_id'] !== $new['stream_id']) {
        report('the bundles are for different streams');
    }

    if ($old['range_from'] !== 1 || $new['range_from'] !== 1) {
        report('consistency requires both bundles to start at sequence 1 (cumulative roots are only computable from the full log)');
    }

    if ($old['range_to'] > $new['range_to']) {
        report('the old bundle covers more events than the new one — pass the older bundle first');
    }

    $consistency = null;

    if ($failures === []) {
        $oldLeaves = $old['leaves'];
        $newLeaves = $new['leaves'];

        $oldRoot = merkle_root($oldLeaves);
        $newRoot = merkle_root($newLeaves);
        $prefixRoot = merkle_root(array_slice($newLeaves, 0, $old['range_to']));

        if (! hash_equals($oldRoot, $prefixRoot)) {
            report('the new bundle does NOT extend the old one: its first '.$old['range_to'].' entries hash to a different root — history diverged');
        } else {
            $proof = consistency_proof($newLeaves, $old['range_to']);

            if (! consistency_verify($old['range_to'], $new['range_to'], $oldRoot, $newRoot, $proof)) {
                report('internal error: the generated consistency proof does not verify');
            } else {
                $consistency = [
                    'old' => ['tree_size' => $old['range_to'], 'root' => bin2hex($oldRoot)],
                    'new' => ['tree_size' => $new['range_to'], 'root' => bin2hex($newRoot)],
                    'proof_nodes' => count($proof),
                ];

                out('  old  tree_size='.$old['range_to'].' root='.bin2hex($oldRoot)."\n");
                out('  new  tree_size='.$new['range_to'].' root='.bin2hex($newRoot)."\n");
                out('  proof '.count($proof)." node(s) verified\n");
            }
        }
    }

    out("\n");

    $code = verdict_code();

    if ($code === EXIT_FAIL) {
        out('FAIL: '.count($failures)." problem(s) found. Consistency does NOT hold.\n");
    } else {
        out("PASS: the new bundle is an append-only extension of the old bundle.\n");
        out("Nothing recorded in the old export was modified, deleted, or reordered in the new one.\n");
    }

    conclude($code, [
        'mode' => 'consistency-bundles',
        'bundles' => [
            ['path' => $targets[0], 'stream' => $old['stream_id'], 'range' => ['from' => $old['range_from'], 'to' => $old['range_to']]],
            ['path' => $targets[1], 'stream' => $new['stream_id'], 'range' => ['from' => $new['range_from'], 'to' => $new['range_to']]],
        ],
        'consistency' => $consistency,
    ]);
}

if (count($targets) === 1 && is_string($recordedRoot) && is_int($recordedSize)) {
    out("Mode:   consistency against a recorded root\n\n");
    out("Bundle: {$targets[0]}\n\n");

    // The recorded size is known before verification, so the root at that
    // size is captured as the events stream past rather than rebuilt from
    // an array of them afterwards.
    $bundle = verify_bundle($targets[0], $skipAnchors, wantedRootSizes: [$recordedSize]);

    out("\nChecking consistency (RFC 6962)...\n");

    if ($bundle['range_from'] !== 1) {
        report('consistency requires the bundle to start at sequence 1');
    } elseif ($recordedSize < 1 || $recordedSize > $bundle['range_to']) {
        report("the recorded size {$recordedSize} is outside this bundle's range");
    } elseif (strlen($recordedRoot) !== 64 || ! ctype_xdigit($recordedRoot)) {
        report('the recorded root is not a 64-character hex hash');
    } else {
        $prefixRoot = $bundle['cumulative_roots'][$recordedSize] ?? '';

        if (! hash_equals($recordedRoot, $prefixRoot)) {
            report("this bundle does NOT extend the recorded state: its first {$recordedSize} entries hash to {$prefixRoot}, not the recorded root");
        } else {
            out("  recorded tree_size={$recordedSize} root={$recordedRoot} — matches this bundle's prefix\n");
        }
    }

    out("\n");

    $code = verdict_code();

    if ($code === EXIT_FAIL) {
        out('FAIL: '.count($failures)." problem(s) found. Consistency does NOT hold.\n");
    } else {
        out("PASS: this bundle is an append-only extension of the recorded state.\n");
    }

    conclude($code, [
        'mode' => 'consistency-recorded-root',
        'bundle' => [
            'path' => $targets[0],
            'stream' => $bundle['stream_id'],
            'range' => ['from' => $bundle['range_from'], 'to' => $bundle['range_to']],
        ],
        'recorded' => ['tree_size' => $recordedSize, 'root' => $recordedRoot],
    ]);
}

if (! $quiet && ! $jsonMode) {
    fwrite(STDERR, $usage);
}

fail_hard('invalid combination of arguments', 2);
