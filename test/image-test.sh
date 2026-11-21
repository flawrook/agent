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

# Builds the container image from dist/release's binaries (the release gate's "image" step), as
# .github/workflows/release-sign.yml does with the same pinned BuildKit, and checks it without pushing anything:
# one index with linux/amd64 and linux/arm64, user 65532 with HOME set, the agent as the entrypoint, and each
# platform's binary answers --version with the release's version under the chart's restrictions (read-only root,
# no capabilities, no privilege escalation). Docker only; the builder and the test images are removed at the end.
#   test/image-test.sh <dir> <version>     after scripts/release.sh <version>
set -u
cd "$(dirname "$0")/.." || exit 1
VERSION=${2:?usage: test/image-test.sh <dir> <version>}
mkdir -p "$1" && OUT=$(cd "$1" && pwd) || exit 1
BUILDKIT_IMAGE=$(sed -n 's/.*--driver-opt image=\(moby\/buildkit:[^ ]*\).*/\1/p' .github/workflows/release-sign.yml)
NAME=flawrook-agent-image-$$
checks=0
fails=0
ok() { checks=$((checks + 1)); echo "  ok $1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); echo "  FAIL $1"; }

for arch in amd64 arm64; do
  [ -f "dist/release/flawrook-agent-linux-$arch" ] || { echo "no dist/release/flawrook-agent-linux-$arch: run scripts/release.sh first" >&2; exit 1; }
done
[ -n "$BUILDKIT_IMAGE" ] || { echo "no BuildKit image in .github/workflows/release-sign.yml" >&2; exit 1; }
cleanup() {
  docker rmi "$NAME:amd64" "$NAME:arm64" >/dev/null 2>&1
  docker buildx rm "$NAME" >/dev/null 2>&1
}
trap cleanup EXIT
# Capped like every container on a shared machine: 4 CPUs, 4 GB.
docker buildx create --name "$NAME" --driver docker-container --driver-opt "image=$BUILDKIT_IMAGE" \
  --driver-opt cpuset-cpus=0-3 --driver-opt memory=4g --driver-opt memory-swap=4g >/dev/null || exit 1
build() { # extra buildx arguments
  docker buildx build --builder "$NAME" --file packaging/Dockerfile --build-arg "VERSION=$VERSION" --provenance=false --sbom=false "$@" dist/release
}

echo "build, both platforms, into $OUT/image.tar"
if build --platform linux/amd64,linux/arm64 --output "type=oci,dest=$OUT/image.tar" >"$OUT/build.log" 2>&1; then
  ok "built"
else
  bad "built: $(tail -5 "$OUT/build.log" | tr '\n' ' ')"
  echo "image: $checks checks, $fails failed"
  exit 1
fi
# The index and each platform's config, read from the OCI layout in the tar.
python3 -I - "$OUT/image.tar" "$VERSION" >"$OUT/config.txt" <<'EOF'
import json, sys, tarfile
t = tarfile.open(sys.argv[1])
blob = lambda d: json.load(t.extractfile("blobs/sha256/" + d.split(":", 1)[1]))
index = blob(json.load(t.extractfile("index.json"))["manifests"][0]["digest"])
print("platforms", " ".join(sorted(m["platform"]["os"] + "/" + m["platform"]["architecture"] for m in index["manifests"])))
for m in index["manifests"]:
    arch = m["platform"]["architecture"]
    c = blob(blob(m["digest"])["config"]["digest"])["config"]
    print(arch, "user", c.get("User"))
    print(arch, "entrypoint", " ".join(c.get("Entrypoint") or []))
    print(arch, "home", " ".join(e for e in c.get("Env", []) if e.startswith("HOME=")))
    print(arch, "version", c.get("Labels", {}).get("org.opencontainers.image.version"))
EOF
line() { grep -qxF -- "$1" "$OUT/config.txt"; }
if line "platforms linux/amd64 linux/arm64"; then ok "one index: linux/amd64 and linux/arm64"; else bad "platforms: $(grep '^platforms' "$OUT/config.txt")"; fi
for arch in amd64 arm64; do
  if line "$arch user 65532:65532"; then ok "$arch: user 65532"; else bad "$arch: $(grep "^$arch user" "$OUT/config.txt")"; fi
  if line "$arch entrypoint /usr/bin/flawrook-agent"; then ok "$arch: the agent is the entrypoint"; else bad "$arch: $(grep "^$arch entrypoint" "$OUT/config.txt")"; fi
  if line "$arch home HOME=/home/nonroot"; then ok "$arch: HOME set"; else bad "$arch: $(grep "^$arch home" "$OUT/config.txt")"; fi
  if line "$arch version $VERSION"; then ok "$arch: labelled $VERSION"; else bad "$arch: $(grep "^$arch version" "$OUT/config.txt")"; fi
done

echo "each platform's binary, run as the chart runs it"
for arch in amd64 arm64; do
  if ! build --platform "linux/$arch" --tag "$NAME:$arch" --load >>"$OUT/build.log" 2>&1; then
    bad "$arch: loaded"
    continue
  fi
  out=$(docker run --rm --name "$NAME-$arch" --label org.flawrook.agent=build --platform "linux/$arch" --memory 128m \
    --read-only --cap-drop ALL --security-opt no-new-privileges "$NAME:$arch" --version 2>&1)
  case "$out" in
  "flawrook-agent $VERSION "*) ok "$arch: $out" ;;
  *) bad "$arch: --version said: $out" ;;
  esac
done

echo "image: $checks checks, $fails failed"
[ "$fails" -eq 0 ]
