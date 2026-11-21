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

# Writes a release's install.sh to stdout: packaging/install.sh with the version and the release's cosign public
# key, the one its checksums.txt is signed with.
#   scripts/render-install.sh 0.2.0 packaging/cosign.pub >dist/release/install.sh
set -eu
VERSION=${1:?usage: scripts/render-install.sh <version> <cosign public key>}
PUB=${2:?usage: scripts/render-install.sh <version> <cosign public key>}
grep -q '^-----BEGIN PUBLIC KEY-----$' "$PUB" || { echo "$PUB isn't a PEM public key" >&2; exit 1; }
cd "$(dirname "$0")/.."
awk -v version="$VERSION" -v pub="$PUB" '
  $0 == "@COSIGN_PUB@" { while ((getline line < pub) > 0) print line; next }
  { gsub(/@VERSION@/, version); print }
' packaging/install.sh
