#!/usr/bin/env sh
# Runs one fuzz target for a budget and fails only on a real finding.
#
#   tools/fuzz.sh ./internal/cjson FuzzParse 60s
#
# go test -fuzz can end with "context deadline exceeded" and exit 1 when
# the budget expires while a worker is still executing an input: the run
# is over, nothing was found, and the status is misleading. A finding
# looks different - the fuzzer writes the input under
# testdata/fuzz/<target>/ and says so, and a seed corpus entry that fails
# is named in the output - so this tells the two apart rather than
# ignoring a class of failure wholesale.
set -eu

pkg="${1:?package, for example ./internal/cjson}"
target="${2:?fuzz target, for example FuzzParse}"
budget="${3:-60s}"

dir="${pkg#./}/testdata/fuzz/$target"
before="$(ls -1 "$dir" 2>/dev/null | sort || true)"

set +e
out="$(go test "$pkg" -run '^$' -fuzz="^${target}\$" -fuzztime="$budget" 2>&1)"
status=$?
set -e

printf '%s\n' "$out"

after="$(ls -1 "$dir" 2>/dev/null | sort || true)"

if [ "$before" != "$after" ]; then
  echo "$target: the fuzzer wrote a new input under $dir - that is a finding"
  exit 1
fi

if [ "$status" -eq 0 ]; then
  exit 0
fi

# Anything the fuzzer names as a failure of an input is a finding, budget
# or no budget.
if printf '%s' "$out" | grep -qE 'failure while testing seed corpus entry|Failing input written|panic:|DATA RACE'; then
  exit "$status"
fi

if printf '%s' "$out" | grep -q 'context deadline exceeded'; then
  echo "$target: the budget expired while a worker was still running; no input failed"
  exit 0
fi

exit "$status"
