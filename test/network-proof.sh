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

# Network proof, Docker only: what the agent connects to. It runs in a container on an internal Docker
# network, which has no route out, so the only endpoints are the stub and a CONNECT proxy in front of it.
# Every connect(2) of the agent and its threads is traced (strace -f), and every packet in its network
# namespace is captured (tcpdump). Three runs:
#   1. --dry-run: no connection at all, and no DNS lookup.
#   2. A report and then a heartbeat to FLAWROOK_URL: connections to the stub only, and DNS for its host only.
#   3. The same through HTTPS_PROXY: connections to the proxy only, and DNS for the proxy's host only.
#   4. sbom over a docker archive of this proof's tools image: no connection, no DNS lookup, and no config file opened.
# Docker's DNS (127.0.0.11) answers the lookups; those connections are the resolver's and are listed apart.
# Usage: test/network-proof.sh [out-dir]
# PREBUILT=1 uses dist/flawrook-agent-linux-<arch> and dist/stub-linux-<arch> as they are, without building.
set -eu
cd "$(dirname "$0")/.."
OUT=${1:-$PWD/dist/network-proof}
ARCH=$(docker version --format '{{.Server.Arch}}')
NET=flawrook-agent-netproof-$$
ALPINE=alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
TOOLS=flawrook-agent-netcheck:local
AGENT=$PWD/dist/flawrook-agent-linux-$ARCH
STUB=$PWD/dist/stub-linux-$ARCH

rm -rf "$OUT"
mkdir -p "$OUT/stub"
if [ "${PREBUILT:-}" = 1 ]; then # the binaries from an earlier build, so a run on a busy machine compiles nothing
  for f in "$AGENT" "$PWD/dist/stub-linux-$ARCH"; do [ -x "$f" ] || { echo "PREBUILT=1, but $f isn't built" >&2; exit 1; }; done
else
  GOARCH=$ARCH scripts/docker-go.sh build -ldflags "-s -w -X main.version=0.1.0" -o "dist/flawrook-agent-linux-$ARCH" ./cmd/flawrook-agent
  GOARCH=$ARCH scripts/docker-go.sh build -o "dist/stub-linux-$ARCH" ./test/stub
fi
# strace and tcpdump, installed while building with the network; the runs below have none.
printf 'FROM %s\nRUN apk add --no-cache strace tcpdump\n' "$ALPINE" | docker build -q -t "$TOOLS" - >/dev/null

# shellcheck disable=SC2317 # run by the trap
cleanup() {
  docker stop -t 2 "$NET-stub" "$NET-proxy" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create --internal "$NET" >/dev/null
docker run -d --rm --name "$NET-stub" --network "$NET" --network-alias stub --memory 128m -v "$STUB:/stub:ro" -v "$OUT/stub:/out" \
  "$ALPINE" /stub -token flra_test >/dev/null
docker run -d --rm --name "$NET-proxy" --network "$NET" --network-alias proxy --memory 128m -v "$STUB:/stub:ro" "$ALPINE" /stub -proxy :3128 >/dev/null
i=0
until [ -s "$OUT/stub/ca.pem" ]; do i=$((i + 1)); [ $i -lt 50 ] || { echo "the stub didn't start"; exit 1; }; sleep 0.2; done
STUB_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NET-stub")
PROXY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NET-proxy")

# run <name> <agent arguments> [-e ...]: the agent under strace (Go's SIGURG preemption signals left out), with
# tcpdump capturing all the while; after 45 s at most the agent gets SIGTERM, as from systemctl stop. TRACE names the
# system calls traced (connect, unless set).
TRACE=connect
run() {
  name=$1 args=$2
  shift 2
  docker run --rm --network "$NET" --hostname "proof-$name" --memory 512m -v "$AGENT:/usr/bin/flawrook-agent:ro" -v "$OUT:/out" \
    -e FLAWROOK_URL=https://stub:8443 -e FLAWROOK_TOKEN=flra_test -e FLAWROOK_CA_FILE=/out/stub/ca.pem "$@" "$TOOLS" sh -c "
      tcpdump -i any -n -U -w /out/$name.pcap 2>/dev/null & dump=\$!
      sleep 1
      strace -f -qq -e trace=$TRACE -e signal=none -o /out/$name.strace /usr/bin/flawrook-agent $args >/out/$name.out 2>/out/$name.log & s=\$!
      i=0; while kill -0 \$s 2>/dev/null && [ \$i -lt 45 ]; do sleep 1; i=\$((i + 1)); done
      pkill -TERM -f '^/usr/bin/flawrook-agent'; wait \$s # busybox's pkill -x doesn't match it by name
      sleep 1; kill \$dump; wait \$dump 2>/dev/null; true"
}
run dry-run --dry-run
run direct "--interval 20s"
run proxy "--interval 20s" -e HTTPS_PROXY=http://proxy:3128
docker save -o "$OUT/image.tar" "$TOOLS"
TRACE=connect,openat
run sbom "sbom --out /out/sbom.json /out/image.tar"
TRACE=connect

# What each run reached: the TCP/UDP endpoints it connected to, and the names it looked up.
fail=0
summary() {
  name=$1 want=$2
  endpoints=$(sed -nE 's/.*sin6?_port=htons\(([0-9]+)\).*(inet_addr\("|inet_pton\(AF_INET6, ")([^"]+)".*/\3:\1/p' "$OUT/$name.strace" |
    sort | uniq -c | awk '{print $2 "*" $1}' | tr '\n' ' ')
  unix=$(grep -c 'AF_UNIX' "$OUT/$name.strace" || true)
  # Docker's resolver remaps port 53 inside the container, so its packets are decoded as DNS by host, not port.
  names=$(docker run --rm --memory 128m -v "$OUT:/out" "$TOOLS" tcpdump -r "/out/$name.pcap" -n -T domain 'udp and host 127.0.0.11' 2>/dev/null |
    grep -oE ' (A|AAAA)\? [^ ]+' | sed 's/ $//' | sort -u | tr '\n' ' ')
  syns=$(docker run --rm --memory 128m -v "$OUT:/out" "$TOOLS" tcpdump -r "/out/$name.pcap" -n 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null |
    grep -oE '> [0-9.]+\.[0-9]+:' | sort | uniq -c | awk '{print $3 "x" $1}' | tr '\n' ' ')
  echo "$name: connect() to ${endpoints:-nothing}; AF_UNIX ${unix}; DNS queries ${names:-none}; TCP SYNs to ${syns:-none}"
  # Allowed: the expected endpoint, and the resolver (127.0.0.11:53).
  extra=$(echo "$endpoints" | tr ' ' '\n' | grep -v "^$" | grep -vE "^($want|127\.0\.0\.11:53)\*" || true)
  [ -z "$extra" ] || { echo "  FAIL: unexpected endpoints: $extra"; fail=1; }
  other=$(echo "$names" | tr ' ' '\n' | grep -E '\.$' | grep -vxE "${3:-NONE}\." || true)
  [ -z "$other" ] || { echo "  FAIL: unexpected names looked up: $other"; fail=1; }
}
summary dry-run 'none'
summary direct "$STUB_IP:8443" stub
summary proxy "$PROXY_IP:3128" proxy
summary sbom 'none'
if grep -E 'openat\(.*"/etc/flawrook' "$OUT/sbom.strace"; then echo "  FAIL: sbom opened a config file"; fail=1; fi
if grep -q '"specVersion":"1.7"' "$OUT/sbom.json" 2>/dev/null; then echo "sbom: $(grep -o '"name":"[^"]*"' "$OUT/sbom.json" | wc -l | tr -d ' ') names in the SBOM, no file under /etc/flawrook opened"
else echo "  FAIL: sbom wrote no SBOM: $(cat "$OUT/sbom.log")"; fail=1; fi
grep -h 'msg="report sent"\|msg="heartbeat sent"' "$OUT/direct.log" "$OUT/proxy.log" | sed -E 's/.*msg="([^"]+)".*status=([0-9]+).*/  \1 \2/' | sort | uniq -c
docker logs "$NET-proxy" 2>&1 | grep CONNECT | sort | uniq -c
echo "stub $STUB_IP, proxy $PROXY_IP"
exit $fail
