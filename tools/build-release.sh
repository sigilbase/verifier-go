#!/usr/bin/env sh
# Builds the release binaries reproducibly. Given the same Go toolchain (the
# one go.mod pins) and the same tag, two clean checkouts produce identical
# bytes: CGO is off, paths are trimmed, VCS stamping is off, the build id
# and symbol tables are stripped, and the version comes from the tag through
# the linker rather than from anything in the working tree.
#
#   tools/build-release.sh <version> [<output directory>]
#
# Writes sigilbase-verify_<version>_<os>_<arch>[.exe] for every target plus
# SHA256SUMS over them and result.schema.json.
set -eu

version="${1:?version, for example 1.6.0}"
out="${2:-dist}"
mkdir -p "$out"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  os="${target%/*}"
  arch="${target#*/}"
  name="sigilbase-verify_${version}_${os}_${arch}"
  if [ "$os" = windows ]; then
    name="$name.exe"
  fi
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOFLAGS= go build \
    -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X github.com/sigilbase/verifier-go/verify.Version=$version" \
    -o "$out/$name" ./cmd/sigilbase-verify
  echo "built $out/$name"
done

cp result.schema.json "$out/"
(cd "$out" && sha256sum sigilbase-verify_* result.schema.json > SHA256SUMS)
cat "$out/SHA256SUMS"
