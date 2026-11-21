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

# The release gate in one pass: every check a public release needs, each with its log under
# dist/gate/<version>-<UTC time>/, and SUMMARY.txt with PASS or FAIL, the time and the key numbers per step.
#   scripts/release-gate.sh 0.1.0
# Docker only. Heavy: it builds both architectures and runs the install test (systemd in a privileged
# container), the integration test (four distribution containers), the network proof and the mutation
# check, and checks the Helm chart (test/chart-test.sh) and the container image (test/image-test.sh). Run it
# when the machine is otherwise quiet. GATE_HEALTH_URL, if set, is checked before each heavy step, and the gate
# stops when it fails or takes more than 1 s. It is also watched every 30 s for the whole
# run: a failure or more than 1 s stops the gate's own containers (never another's), goes into health.log,
# and marks the running step STOPPED; the watch goes on. GATE_STEPS="vet test …" runs only those steps.
# release.sh puts packaging/cosign.pub into install.sh, or COSIGN_PUB's key; it signs nothing (release-sign.yml does).
set -u
VERSION=${1:?usage: scripts/release-gate.sh <version>}
cd "$(dirname "$0")/.." || exit 1
OUT=$PWD/dist/gate/$VERSION-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT"
GO_IMAGE=$(sed -n 's/^GO_IMAGE=//p' scripts/docker-go.sh)
SHELLCHECK_IMAGE=koalaman/shellcheck-alpine:v0.10.0@sha256:5921d946dac740cbeec2fb1c898747b6105e585130cc7f0602eec9a10f7ddb63
unset FLAWROOK_URL FLAWROOK_TOKEN # the tests use their own stub and test token
fail=0

healthy() {
  [ -n "${GATE_HEALTH_URL:-}" ] || return 0
  r=$(curl -s -o /dev/null -m 3 -w '%{http_code} %{time_total}' "$GATE_HEALTH_URL" || echo "000 3")
  [ "${r% *}" = 200 ] && [ "$(echo "${r#* } <= 1" | bc)" = 1 ]
}

# The gate's own containers: its Go and nfpm runs by their label (docker-go.sh, licences.sh, release.sh and gofmt
# set org.flawrook.agent=build), and the tests' flawrook-agent-install-, -it- and -netproof- containers by name
# or network. This Docker may be shared, so nothing else is matched.
gate_containers() {
  {
    docker ps -q --filter label=org.flawrook.agent=build
    docker ps --format '{{.ID}} {{.Names}} {{.Networks}}' |
      awk '$2 ~ /^(buildx_buildkit_)?flawrook-agent-(install|it|netproof|image)-[0-9]/ || $3 ~ /flawrook-agent-(install|it|netproof)-[0-9]/ {print $1}'
  } | sort -u
}
breaches() { if [ -f "$OUT/health.log" ]; then wc -l <"$OUT/health.log" | tr -d ' '; else echo 0; fi; }
if [ -n "${GATE_HEALTH_URL:-}" ]; then
  while :; do
    if ! healthy; then
      ids=$(gate_containers | tr '\n' ' ')
      echo "$(date -u +%FT%TZ) $GATE_HEALTH_URL answered $r; stopped: ${ids:-nothing}" >>"$OUT/health.log"
      # shellcheck disable=SC2086 # one argument per container id
      [ -z "$ids" ] || docker stop -t 2 $ids >/dev/null 2>&1
    fi
    sleep 30
  done &
  watch=$!
  trap 'kill $watch 2>/dev/null' EXIT
  trap 'exit 130' INT TERM
fi

# note <step>: the key numbers from its log, for the summary.
note() {
  log=$OUT/$1.log
  case $1 in
    test) echo "$(grep -c '^--- PASS' "$log") passed, $(grep -c '^--- FAIL' "$log") failed, $(grep -c '^ok ' "$log") packages ok" ;;
    gofmt) echo "$(grep -vc '^$' "$log") files unformatted" ;;
    licences) tail -1 "$log" ;;
    artifacts) grep -cE '^[0-9a-f]{64}  ' "$OUT/checksums.txt" | sed 's/$/ files checksummed/' ;;
    signature) tail -1 "$log" ;;
    unit-caps) grep -c '^--- PASS' "$log" | sed 's/$/ unit test passed; the built unit equals packaging\/flawrook-agent.service/' ;;
    install-test) echo "$(grep -c '  ok ' "$log") ok, $(grep -c 'FAIL' "$log") failed; $(grep -o 'exposure level[^:]*: [0-9.]* [A-Z]*' "$log")" ;;
    integration) grep -E '^[a-z0-9-]+: reports=' "$log" | sed -E 's/ maxRssKiB.*//' | tr '\n' ';' ;;
    network-proof) grep -E '^(dry-run|direct|proxy):' "$log" | cut -d';' -f1 | tr '\n' ';' ;;
    mutants) tail -1 "$log" ;;
    chart) tail -1 "$log" ;;
    image) tail -1 "$log" ;;
  esac
}

# step <name> <heavy 0|1> <command…>: runs it, its output to <name>.log, its line to SUMMARY.txt.
step() {
  name=$1 heavy=$2
  shift 2
  case " ${GATE_STEPS:-$name} " in *" $name "*) ;; *) return 0 ;; esac # GATE_STEPS: run only these (a dry check)
  if [ "$heavy" = 1 ] && ! healthy; then
    echo "STOPPED before $name: $GATE_HEALTH_URL answered ${r:-nothing}" | tee -a "$OUT/SUMMARY.txt"
    exit 2
  fi
  start=$(date +%s) seen=$(breaches)
  if "$@" >"$OUT/$name.log" 2>&1; then res=PASS; else res=FAIL fail=1; fi
  [ "$(breaches)" = "$seen" ] || res=STOPPED fail=1 # the health watch stopped its containers
  printf '%-14s %s %5ss  %s\n' "$name" "$res" $(($(date +%s) - start)) "$(note "$name")" | tee -a "$OUT/SUMMARY.txt"
}

# shellcheck disable=SC2317 # gofmt_clean, built_unit_is_packaged and artifacts run through step
gofmt_clean() { # gofmt lists unformatted files; none may be listed (third_party holds licence texts only)
  docker run --rm --label org.flawrook.agent=build --memory 512m -v "$PWD":/src -w /src "$GO_IMAGE" gofmt -l . | grep -v '^third_party/' | tee /dev/stderr | grep -q . && return 1
  return 0
}
# shellcheck disable=SC2317
built_unit_is_packaged() {
  scripts/docker-go.sh test -count=1 -run TestTheSystemdUnit -v ./packaging/ && cmp dist/release/flawrook-agent.service packaging/flawrook-agent.service
}
# shellcheck disable=SC2317
signature() { # release.sh signs nothing: install.sh carries the release key, and the workflow that signs is pinned
  sed -n '/^-----BEGIN PUBLIC KEY-----$/,/^-----END PUBLIC KEY-----$/p' dist/release/install.sh >"$OUT/install.pub"
  cmp "$OUT/install.pub" "${COSIGN_PUB:-packaging/cosign.pub}" || { echo "install.sh carries another key"; return 1; }
  [ ! -e dist/release/checksums.txt.sig ] || { echo "release.sh made a signature: signing is release-sign.yml's"; return 1; }
  wf=.github/workflows/release-sign.yml
  # Every action pinned to a full commit SHA, its version beside it; cosign's own version set.
  uses=$(grep -cE '^ *- uses: ' "$wf")
  pinned=$(grep -cE '^ *- uses: [^@ ]+@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$' "$wf")
  if [ "$uses" = 0 ] || [ "$uses" != "$pinned" ]; then echo "$wf: $pinned of $uses actions pinned to a commit SHA"; return 1; fi
  grep -q '^ *- uses: sigstore/cosign-installer@' "$wf" || { echo "$wf doesn't install cosign with sigstore/cosign-installer"; return 1; }
  cosign=$(sed -nE 's/^ *cosign-release: (v[0-9]+\.[0-9]+\.[0-9]+)( .*)?$/\1/p' "$wf")
  [ -n "$cosign" ] || { echo "$wf doesn't set cosign's version"; return 1; }
  # The least it needs: no permission at the top, contents: write for its one job, the two cosign secrets only.
  secrets=$(grep -oE 'secrets\.[A-Za-z_]+' "$wf" | sort -u | tr '\n' ' ')
  [ "$secrets" = "secrets.COSIGN_PASSWORD secrets.COSIGN_PRIVATE_KEY " ] || { echo "$wf uses the secrets: $secrets"; return 1; }
  grep -q '^permissions: {}$' "$wf" || { echo "$wf grants permissions at the top"; return 1; }
  if [ "$(grep -cE '^ +[a-z-]+: (read|write)( |$)' "$wf")" != 1 ] || ! grep -qE '^ +contents: write( |$)' "$wf"; then
    echo "$wf: its job's permissions aren't contents: write alone"
    return 1
  fi
  echo "install.sh carries the release key; $wf: $pinned actions pinned by SHA, cosign $cosign, contents: write only, the two cosign secrets only"
}
# shellcheck disable=SC2317
artifacts() {
  cp dist/release/checksums.txt "$OUT/checksums.txt"
  ls -l dist/release
  (cd dist/release && shasum -a 256 -c checksums.txt)
}

echo "release gate $VERSION, logs in $OUT"
step vet           0 scripts/docker-go.sh vet ./...
step test          0 scripts/docker-go.sh test -count=1 -v ./...
step gofmt         0 gofmt_clean
step shellcheck    0 docker run --rm --memory 256m -v "$PWD":/mnt:ro --entrypoint sh "$SHELLCHECK_IMAGE" -c 'shellcheck -s sh /mnt/packaging/*.sh /mnt/scripts/*.sh /mnt/test/*.sh'
step headers       0 scripts/headers.sh
step licences      0 scripts/licences.sh --check
step chart         0 test/chart-test.sh "$OUT/chart"
step release       1 scripts/release.sh "$VERSION"
step unit-caps     0 built_unit_is_packaged
step artifacts     0 artifacts
step signature     0 signature
step image         1 test/image-test.sh "$OUT/image" "$VERSION"
step install-test  1 test/install-test.sh "$OUT/install-test"
step integration   1 test/integration.sh "$OUT/integration"
step network-proof 1 test/network-proof.sh "$OUT/network-proof"
step mutants       1 python3 -B test/mutants.py
if [ $fail = 0 ]; then echo "GATE PASSED"; else echo "GATE FAILED"; fi | tee -a "$OUT/SUMMARY.txt"
exit $fail
