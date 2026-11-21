#!/bin/sh
# Copyright 2026 Binerals Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds a release's files locally into dist/release, Docker only; nothing is published from here.
#   scripts/release.sh 0.1.0
# Out: the binaries, deb and rpm per architecture, install.sh with the version and the release's cosign public key
# in it (packaging/cosign.pub, or COSIGN_PUB for a test key), the systemd unit, and checksums.txt (sha256, the file
# install.sh checks). Nothing is signed here: publishing the release as a prerelease runs
# .github/workflows/release-sign.yml, which signs checksums.txt with the private key, a repository secret, and
# only then makes the release the latest.
set -eu
VERSION=${1:?usage: scripts/release.sh <version>}
NFPM_IMAGE=goreleaser/nfpm:v2.48.0@sha256:d57a1452e7a019896b355f7b1ec67262278f6c503631f652d4fce7aef9ac8df7
COSIGN_PUB=${COSIGN_PUB:-packaging/cosign.pub}
[ -f "$COSIGN_PUB" ] || { echo "no public key at $COSIGN_PUB (packaging/cosign.pub, or COSIGN_PUB)" >&2; exit 1; }
: "${MAINTAINER:=Binerals Ltd <hello@flawrook.com>}" # the one maintainer value nfpm.yaml takes
cd "$(dirname "$0")/.."
scripts/licences.sh --check # every linked module's licence files ship
rm -rf dist/release
mkdir -p dist/release
for arch in amd64 arm64; do
  GOARCH=$arch scripts/docker-go.sh build -ldflags "-s -w -X main.version=$VERSION" -o "dist/release/flawrook-agent-linux-$arch" ./cmd/flawrook-agent
  mkdir -p dist/pkg
  cp "dist/release/flawrook-agent-linux-$arch" dist/pkg/flawrook-agent
  for packager in deb rpm; do
    case "$packager-$arch" in deb-*) target=flawrook-agent-$arch.deb ;; rpm-amd64) target=flawrook-agent-x86_64.rpm ;; rpm-arm64) target=flawrook-agent-aarch64.rpm ;; esac
    docker run --rm --label org.flawrook.agent=build -v "$PWD":/src -w /src -e VERSION="$VERSION" -e GOARCH="$arch" -e MAINTAINER="$MAINTAINER" "$NFPM_IMAGE" \
      package --config packaging/nfpm.yaml --packager "$packager" --target "dist/release/$target" >/dev/null
  done
done
rm -r dist/pkg
scripts/render-install.sh "$VERSION" "$COSIGN_PUB" >dist/release/install.sh
cp packaging/flawrook-agent.service dist/release/
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
(cd dist/release && for f in *; do printf '%s  %s\n' "$(sha256 "$f")" "$f"; done >../checksums.txt)
mv dist/checksums.txt dist/release/checksums.txt
ls -l dist/release
