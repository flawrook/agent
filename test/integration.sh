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

# Integration run, Docker only: the agent binary scans debian:12, ubuntu:24.04, alpine:3.20 and
# rockylinux:9 containers and reports to the stub over TLS, trusting the stub's test CA through
# FLAWROOK_CA_FILE. Each container runs the agent with --interval 20s for RUN_SECONDS, so it sends a
# report and then heartbeats; the stub answers the first heartbeat it gets with 409, so one host also
# shows a heartbeat turning into a full report. A --dry-run per image is kept beside the logs.
# Usage: test/integration.sh [out-dir]
# PREBUILT=1 uses dist/flawrook-agent-linux-<arch> and dist/stub-linux-<arch> as they are, without building.
# Against a real API instead of the stub: export FLAWROOK_URL and FLAWROOK_TOKEN (the token passes to the
# containers by name only). An API on this machine's loopback (http://127.0.0.1:<port>) is reached through
# a forwarder in each agent container, so the agent sees it as its own loopback and its rule (plain http
# only to loopback) stays as it is.
set -eu
cd "$(dirname "$0")/.."
OUT=${1:-$PWD/dist/integration}
IMAGES=${IMAGES:-"debian:12 ubuntu:24.04 alpine:3.20 rockylinux:9"}
RUN_SECONDS=${RUN_SECONDS:-75}
ARCH=$(docker version --format '{{.Server.Arch}}')
NET=flawrook-agent-it-$$
AGENT=$PWD/dist/flawrook-agent-linux-$ARCH

rm -rf "$OUT"
mkdir -p "$OUT/stub"
if [ "${PREBUILT:-}" = 1 ]; then # the binaries from an earlier build, so a run on a busy machine compiles nothing
  for f in "$AGENT" "$PWD/dist/stub-linux-$ARCH"; do [ -x "$f" ] || { echo "PREBUILT=1, but $f isn't built" >&2; exit 1; }; done
else
  GOARCH=$ARCH scripts/docker-go.sh build -ldflags "-s -w -X main.version=0.1.0" -o "dist/flawrook-agent-linux-$ARCH" ./cmd/flawrook-agent
  GOARCH=$ARCH scripts/docker-go.sh build -o "dist/stub-linux-$ARCH" ./test/stub
fi

names=""
# shellcheck disable=SC2317 # run by the trap
cleanup() {
  for n in $names; do docker stop -t 2 "$NET-$n" "$NET-$n-fwd" >/dev/null 2>&1 || true; done
  docker stop -t 2 "$NET-stub" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create "$NET" >/dev/null

STUB=""
[ -n "${FLAWROOK_URL:-}" ] || STUB=1
export FLAWROOK_URL="${FLAWROOK_URL:-https://stub:8443}"
export FLAWROOK_TOKEN="${FLAWROOK_TOKEN:-flra_test}"
CA="$OUT/stub/ca.pem"
forward=""
case "$FLAWROOK_URL" in http://127.0.0.1:* | http://localhost:*)
  port=${FLAWROOK_URL##*:}
  forward=${port%%/*} ;;
esac
caopts=""
if [ -n "$STUB" ]; then
  docker run -d --rm --name "$NET-stub" --network "$NET" --network-alias stub \
    -v "$PWD/dist/stub-linux-$ARCH:/stub:ro" -v "$OUT/stub:/out" \
    alpine:3.20 /stub -token "$FLAWROOK_TOKEN" -queue heartbeat:409 >/dev/null
  i=0
  until [ -s "$CA" ]; do i=$((i + 1)); [ $i -lt 50 ] || { echo "the stub didn't start"; exit 1; }; sleep 0.2; done
  caopts="-v $CA:/etc/flawrook/ca.pem:ro -e FLAWROOK_CA_FILE=/etc/flawrook/ca.pem"
fi

for image in $IMAGES; do
  name=$(echo "$image" | tr ':./' '---')
  names="$names $name"
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null
  docker image inspect "$image" --format "$image {{index .RepoDigests 0}}" >>"$OUT/images.txt"
  run="docker run --network $NET --hostname it-$name -v $AGENT:/usr/bin/flawrook-agent:ro -e FLAWROOK_URL -e FLAWROOK_TOKEN $caopts"
  $run --rm "$image" /usr/bin/flawrook-agent --dry-run >"$OUT/$name.dry-run.json" 2>"$OUT/$name.dry-run.log"
  $run -d --rm --name "$NET-$name" "$image" /usr/bin/flawrook-agent --interval 20s >/dev/null
  if [ -n "$forward" ]; then
    docker run -d --rm --name "$NET-$name-fwd" --network "container:$NET-$name" -v "$PWD/dist/stub-linux-$ARCH:/stub:ro" \
      alpine:3.20 /stub -forward "127.0.0.1:$forward=host.docker.internal:$forward" >/dev/null
  fi
done
sleep "$RUN_SECONDS"
for name in $names; do
  docker logs "$NET-$name" >"$OUT/$name.log" 2>&1
  docker stop -t 5 "$NET-$name" >/dev/null
  [ -z "$forward" ] || docker stop -t 2 "$NET-$name-fwd" >/dev/null 2>&1 || true
done

echo "binary: $(wc -c <"$AGENT" | tr -d ' ') bytes ($ARCH)"
fail=0
for name in $names; do
  if [ -n "$STUB" ]; then
    reports=$(grep -c "\"hostname\":\"it-$name\".*\"route\":\"report\",\"status\":202" "$OUT/stub/requests.jsonl" || true)
    heartbeats=$(grep -c "\"hostname\":\"it-$name\".*\"route\":\"heartbeat\",\"status\":204" "$OUT/stub/requests.jsonl" || true)
  else # the agent's own log: a report it sent, and each heartbeat the API answered 2xx
    reports=$(grep -c 'msg="report sent"' "$OUT/$name.log" || true)
    heartbeats=$(grep -c 'msg="heartbeat sent"' "$OUT/$name.log" || true)
  fi
  rss=$(grep -o 'maxRssKiB=[0-9]*' "$OUT/$name.log" | tr '\n' ' ')
  echo "$name: reports=$reports heartbeats=$heartbeats $rss"
  [ "$reports" -ge 1 ] && [ "$heartbeats" -ge 1 ] || fail=1
done
exit $fail
