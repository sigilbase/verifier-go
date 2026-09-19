#!/usr/bin/env sh
# Checks that the material mirrored from the verifier repository is exact
# at the given ref: the corpus, the vectors, the trust material, the schema
# and verify.php. Exit 1 on any difference.
#
#   tools/check-upstream.sh v1.6.0
#   tools/check-upstream.sh go-verifier
set -eu

ref="${1:?a tag, branch or commit of github.com/sigilbase/verifier}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git clone --quiet --depth 1 --branch "$ref" https://github.com/sigilbase/verifier.git "$work/upstream" 2>/dev/null \
  || { git clone --quiet https://github.com/sigilbase/verifier.git "$work/upstream" && git -C "$work/upstream" checkout --quiet "$ref"; }

status=0
compare() {
  if ! diff -r -q "$1" "$2" >/dev/null 2>&1; then
    echo "differs: $1 vs upstream $2"
    diff -r -q "$1" "$2" || true
    status=1
  else
    echo "same:    $1"
  fi
}

compare corpus "$work/upstream/corpus"
compare vectors "$work/upstream/vectors"
compare keys/sigilbase.json "$work/upstream/keys/sigilbase.json"
compare keys/tsa-roots.pem "$work/upstream/keys/tsa-roots.pem"
compare result.schema.json "$work/upstream/result.schema.json"
compare reference/verify.php "$work/upstream/verify.php"

if [ "$status" -ne 0 ]; then
  echo "the mirror is not exact at $ref"
fi
exit "$status"
