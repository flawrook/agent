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

# install.sh and the packages, Docker only, against the local release in dist/release (scripts/release.sh
# first), which the stub serves over HTTP as FLAWROOK_RELEASE_URL:
# 1. No systemd, one-line form: the deb on debian:12 and ubuntu:24.04, the rpm on rockylinux:9, the binary
#    on alpine:3.20. The files, their modes (root and the flawrook group's), the token only in agent.yaml,
#    which a user outside the group can't read. A user in the group, with no capability, reads the token and
#    sends a report, and its --dry-run lists what root's does. A tampered deb is refused.
#    Signatures (debian:12, on a copy of the release signed here as release-sign.yml signs it, with a key pair
#    of this run's own): with cosign installed a good checksums.txt.sig is verified; a checksums.txt changed after
#    signing, a signature by another key, or none stops the install. Without cosign it says so and goes on, unless
#    FLAWROOK_REQUIRE_SIGNATURE=1 stops it.
# 2. systemd as PID 1 (debian:12 plus systemd, built here, privileged): the two-step form starts the
#    service, which reports to the stub as its own user with no capability, reading its config through the
#    flawrook group; a token rotation with the one-line form keeps the other keys and the modes, and
#    systemctl reload rereads it; an agent.yaml left root's alone stops the agent with an error that names
#    the group and the mode; FLAWROOK_READ_PROTECTED=1 adds CAP_DAC_READ_SEARCH and 0 takes it away, and a
#    read_protected that disagrees with the unit is warned about; removal stops it.
#    The service starts exactly once per install (the journal's count): a fresh install with a token, the
#    same package again over the running agent, an upgrade to the next patch version (the same binary,
#    repacked), and none at all without a token. An upgrade from 0.1.0 as released (its 0700 and 0600 modes,
#    its capability) leaves the agent reporting with the new modes and no capability. An upgrade from 0.2.0 as
#    released (the flawrook group's modes already) keeps them, starts the agent once more and reports again.
#    The systemd floor, with a fake systemctl --version: on 219, or a version it can't
#    read, install.sh refuses and changes nothing; on 219 the deb by itself installs its files but neither
#    enables nor starts the service; on 235 install.sh installs and starts it. With systemd 219 installed but
#    not running, install.sh refuses as well, and the deb by itself enables nothing. A systemd that ignores
#    DynamicUser= (a drop-in) starts the agent as root: it refuses with exit status 78, which isn't restarted;
#    as root with the unit's marker --version still answers and --dry-run refuses.
# 3. systemd as PID 1 with rpm (rockylinux:9 plus systemd, built here, privileged): a fresh install with a token
#    starts it once, with the group and no capability; the upgrades to the next two patch versions, with
#    install.sh and by rpm alone, each start it once more and leave it running: rpm runs the new package's
#    %post before the old one's %preun, which must not stop what %post started.
# 4. systemd 237 as PID 1 (ubuntu:18.04 plus systemd, built here, privileged), the oldest the floor takes. It
#    doesn't know @system-service: with the sets and calls the unit lists besides, the service starts, reports,
#    heartbeats, lives through a reload and a token rotation, and is never stopped with SIGSYS.
# Usage: test/install-test.sh [out-dir]
# PREBUILT=1 uses dist/stub-linux-<arch> as it is, without building. The 0.1.0 and 0.2.0 releases come from GitHub
# (PREVIOUS_URL and PREVIOUS_020_URL), each checked against its checksums.txt. Every container is memory-capped.
set -eu
cd "$(dirname "$0")/.."
OUT=${1:-$PWD/dist/install-test}
ARCH=$(docker version --format '{{.Server.Arch}}')
NET=flawrook-agent-install-$$
T1="flra_$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 43)"
T2="flra_$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 43)"
docker image inspect debian:12 >/dev/null 2>&1 || docker pull -q debian:12 >/dev/null
DEBIAN=debian:12@sha256:$(docker image inspect debian:12 --format '{{index .RepoDigests 0}}' | cut -d: -f2)
docker image inspect rockylinux:9 >/dev/null 2>&1 || docker pull -q rockylinux:9 >/dev/null
ROCKY=rockylinux:9@sha256:$(docker image inspect rockylinux:9 --format '{{index .RepoDigests 0}}' | cut -d: -f2)

[ -f dist/release/checksums.txt ] || { echo "run scripts/release.sh first"; exit 1; }
REL=$(sed -n 's/^VERSION=//p' dist/release/install.sh) # the release under test; the upgrades are its next patch versions
bump() { echo "$1" | awk -F. -v n="$2" '{ printf "%s.%s.%d\n", $1, $2, $3 + n }'; }
UP1=$(bump "$REL" 1) UP2=$(bump "$REL" 2)
rm -rf "$OUT"
mkdir -p "$OUT/stub" "$OUT/releases"
# The release's public key, as its install.sh carries it.
sed -n '/^-----BEGIN PUBLIC KEY-----$/,/^-----END PUBLIC KEY-----$/p' dist/release/install.sh >"$OUT/release.pub"
scripts/render-install.sh "$REL" "$OUT/release.pub" | cmp -s - dist/release/install.sh ||
  { echo "dist/release/install.sh is older than packaging/install.sh: run scripts/release.sh"; exit 1; }
cp -Rc dist/release "$OUT/releases/good" 2>/dev/null || cp -R dist/release "$OUT/releases/good"
cp -R "$OUT/releases/good" "$OUT/releases/tampered"
printf x >>"$OUT/releases/tampered/flawrook-agent-$ARCH.deb"
# Signatures. release.sh signs nothing (release-sign.yml signs on GitHub, with the release key), so this run signs
# a copy of the release with a key pair of its own, made here with no network and deleted once used: "signed" is
# the release as release-sign.yml leaves it, its install.sh carrying this run's key. Then the same with
# checksums.txt changed after signing, signed with another key, and not signed at all. The hosts' cosign is the
# version release-sign.yml signs with.
COSIGN_IMAGE=ghcr.io/sigstore/cosign/cosign:v2.6.0@sha256:71b96f6405dd3c3f081ebf73099f18edac7a716699398660890a86c42bf5edfd
mkdir -p "$OUT/keys"
cosign() { docker run --rm --network none --memory 256m -v "$OUT/keys:/k" -v "$OUT/releases:/r" -e COSIGN_PASSWORD=test "$COSIGN_IMAGE" "$@" >/dev/null 2>&1; }
sums() { (cd "$1" && for f in *; do [ "$f" = checksums.txt ] || printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"; done >../sums.tmp) && mv "$1/../sums.tmp" "$1/checksums.txt"; }
cosign generate-key-pair --output-key-prefix /k/test
cosign generate-key-pair --output-key-prefix /k/other
cp -R "$OUT/releases/good" "$OUT/releases/signed"
scripts/render-install.sh "$REL" "$OUT/keys/test.pub" >"$OUT/releases/signed/install.sh"
sums "$OUT/releases/signed"
cosign sign-blob --yes --key /k/test.key --tlog-upload=false --output-signature /r/signed/checksums.txt.sig /r/signed/checksums.txt
for c in changed badsig nosig; do cp -R "$OUT/releases/signed" "$OUT/releases/$c"; done
printf '%s  %s\n' "$(printf x | shasum -a 256 | cut -d' ' -f1)" extra.txt >>"$OUT/releases/changed/checksums.txt"
cosign sign-blob --yes --key /k/other.key --tlog-upload=false --output-signature /r/badsig/checksums.txt.sig /r/badsig/checksums.txt
rm "$OUT/releases/nosig/checksums.txt.sig" "$OUT/keys/test.key" "$OUT/keys/other.key"
if [ ! -s "$OUT/releases/signed/checksums.txt.sig" ] || [ ! -s "$OUT/releases/badsig/checksums.txt.sig" ]; then echo "the test signatures weren't made"; exit 1; fi
id=$(docker create "$COSIGN_IMAGE")
docker cp "$id:/ko-app/cosign" "$OUT/cosign" >/dev/null
docker rm "$id" >/dev/null
# 0.1.0 and 0.2.0 as released, for the upgrades from their modes and 0.1.0's capability.
PREVIOUS_URL=${PREVIOUS_URL:-https://github.com/flawrook/agent/releases/download/v0.1.0}
PREVIOUS_020_URL=${PREVIOUS_020_URL:-https://github.com/flawrook/agent/releases/download/v0.2.0}
for previous in "0.1.0 $PREVIOUS_URL" "0.2.0 $PREVIOUS_020_URL"; do
  v=${previous%% *} url=${previous#* }
  dir=$OUT/releases/v$(echo "$v" | tr -d .)
  mkdir -p "$dir"
  for f in checksums.txt install.sh "flawrook-agent-$ARCH.deb"; do curl -fsSL -o "$dir/$f" "$url/$f"; done
  (cd "$dir" && grep -E "  (install\.sh|flawrook-agent-$ARCH\.deb)\$" checksums.txt | shasum -a 256 -c - >/dev/null) ||
    { echo "$v from $url doesn't match its checksums.txt"; exit 1; }
done
# Upgrades: the same binary as the next patch version's deb and rpm, with its install.sh and checksums.txt, as
# release.sh makes them (unsigned: these hosts have no cosign); and as the one after that's rpm, for rpm alone.
mkdir -p "$OUT/upgrade-src/dist/pkg" "$OUT/releases/direct"
cp -R packaging LICENSE NOTICE third_party "$OUT/upgrade-src/"
# No Go file in the output: under dist/gate/ it would be a package of the module's next `go test ./...`.
rm -f "$OUT/upgrade-src/packaging/"*_test.go
cp "dist/release/flawrook-agent-linux-$ARCH" "$OUT/upgrade-src/dist/pkg/flawrook-agent"
case $ARCH in arm64) RPMARCH=aarch64 ;; *) RPMARCH=x86_64 ;; esac
repack() { # version, deb or rpm, file name
  # shellcheck disable=SC2016 # sed matches release.sh's literal ${MAINTAINER:=…}
  docker run --rm --label org.flawrook.agent=build --memory 512m -v "$OUT/upgrade-src":/src -w /src -e VERSION="$1" -e GOARCH="$ARCH" \
    -e MAINTAINER="$(sed -n 's/^: "${MAINTAINER:=\(.*\)}".*/\1/p' scripts/release.sh)" "$(sed -n 's/^NFPM_IMAGE=//p' scripts/release.sh)" \
    package --config packaging/nfpm.yaml --packager "$2" --target "dist/$3" >/dev/null
}
repack "$UP1" deb "flawrook-agent-$ARCH.deb"
repack "$UP1" rpm "flawrook-agent-$RPMARCH.rpm"
repack "$UP2" rpm "flawrook-agent-$UP2-$RPMARCH.rpm"
cp -R "$OUT/releases/good" "$OUT/releases/upgrade"
cp "$OUT/upgrade-src/dist/flawrook-agent-$ARCH.deb" "$OUT/upgrade-src/dist/flawrook-agent-$RPMARCH.rpm" "$OUT/releases/upgrade/"
cp "$OUT/upgrade-src/dist/flawrook-agent-$UP2-$RPMARCH.rpm" "$OUT/releases/direct/"
scripts/render-install.sh "$UP1" "$OUT/release.pub" >"$OUT/releases/upgrade/install.sh"
(cd "$OUT/releases/upgrade" && for f in *; do [ "$f" = checksums.txt ] || printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"; done >../upgrade-checksums.txt)
mv "$OUT/releases/upgrade-checksums.txt" "$OUT/releases/upgrade/checksums.txt"
if [ "${PREBUILT:-}" = 1 ]; then # the stub from an earlier build, so a run on a busy machine compiles nothing
  [ -x "dist/stub-linux-$ARCH" ] || { echo "PREBUILT=1, but dist/stub-linux-$ARCH isn't built" >&2; exit 1; }
else
  GOARCH=$ARCH scripts/docker-go.sh build -o "dist/stub-linux-$ARCH" ./test/stub
fi

# shellcheck disable=SC2317 # run by the trap
cleanup() {
  docker stop -t 2 "$NET-stub" "$NET-systemd" "$NET-from010" "$NET-from020" "$NET-rocky" "$NET-bionic" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create "$NET" >/dev/null
docker run -d --rm --name "$NET-stub" --network "$NET" --network-alias stub --network-alias releases --memory 128m \
  -v "$PWD/dist/stub-linux-$ARCH:/stub:ro" -v "$OUT/stub:/out" -v "$OUT/releases:/releases:ro" \
  alpine:3.20 /stub -token "$T1,$T2" -releases /releases >/dev/null
i=0
until [ -s "$OUT/stub/ca.pem" ]; do i=$((i + 1)); [ $i -lt 50 ] || { echo "the stub didn't start"; exit 1; }; sleep 0.2; done

fail=0
check() { # what, command output, expected
  if [ "$2" = "$3" ]; then echo "  ok   $1: $2"; else echo "  FAIL $1: got '$2', want '$3'"; fail=1; fi
}
reported() { # hostname, route, [token hint]: how many times the stub accepted it
  grep "\"hostname\":\"$1\"" "$OUT/stub/requests.jsonl" 2>/dev/null | grep "\"route\":\"$2\",\"status\":20[24]" | grep -c "\"token\":\"${3:-}" || true
}

echo "1. No systemd, the one-line form"
# val <key>: one line of the container's key=value answers.
val() { printf '%s\n' "$result" | sed -n "s/^$1=//p"; }
for image in debian:12 ubuntu:24.04 rockylinux:9 alpine:3.20; do
  echo "$image"
  name=$(echo "$image" | tr ':./' '---')
  prep=true
  case "$image" in debian:* | ubuntu:*) prep="apt-get update -qq >/dev/null && apt-get install -y -qq curl >/dev/null 2>&1" ;; esac
  # A user in the flawrook group (the service's place) and one outside it (nobody), neither with a capability.
  result=$(docker run --rm --network "$NET" --memory 512m -v "$PWD/dist/release/install.sh:/install.sh:ro" -v "$OUT/stub/ca.pem:/ca.pem:ro" \
    -e FLAWROOK_RELEASE_URL=http://releases:8080/good -e FLAWROOK_URL=https://stub:8443 -e FLAWROOK_TOKEN="$T1" \
    "$image" sh -c "$prep && sh /install.sh >/tmp/out 2>&1; echo install=\$?
      echo nosystemd=\$(grep -c 'No systemd here' /tmp/out)
      echo nocosign=\$(grep -c \"cosign isn't installed\" /tmp/out)
      b=\$(command -v flawrook-agent); echo version=\$(\$b --version | cut -d' ' -f1-2)
      echo modes=\$(stat -c '%a %U %G' /etc/flawrook /etc/flawrook/agent.yaml | tr '\\n' ' ')
      echo group=\$(grep -c '^flawrook:' /etc/group)
      echo config=\$(grep -cE '^(token: $T1|url: https://stub:8443)\$' /etc/flawrook/agent.yaml)
      echo unittoken=\$(cat /usr/lib/systemd/system/flawrook-agent.service 2>/dev/null | grep -c flra_ || true)
      echo mpl=\$(ls /usr/share/doc/flawrook-agent/third_party/licenses/github.com/hashicorp 2>/dev/null | wc -l)
      echo denied=\$(su -s /bin/sh nobody -c 'cat /etc/flawrook/agent.yaml' 2>&1 | grep -c 'Permission denied')
      if command -v useradd >/dev/null; then useradd -M -N -g flawrook -s /bin/sh svc; else adduser -D -H -G flawrook -s /bin/sh svc; fi
      # A machine ID, as a host has: without one the agent keeps a generated ID in /var/lib/flawrook, which a non-root user can't create.
      [ -s /etc/machine-id ] || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \\n' >/etc/machine-id
      \$b --dry-run 2>/dev/null | grep -o '\"purl\":\"[^\"]*\"' | sort >/tmp/root.txt
      su -s /bin/sh svc -c \"\$b --dry-run 2>/dev/null\" | grep -o '\"purl\":\"[^\"]*\"' | sort >/tmp/svc.txt
      echo purls=\$(grep -c . /tmp/root.txt) \$([ -z \"\$(comm -3 /tmp/root.txt /tmp/svc.txt)\" ] && echo same || echo different) \$(grep -c . /tmp/svc.txt)
      echo purldiff=\$(comm -3 /tmp/root.txt /tmp/svc.txt | head -3 | tr -d '\\t' | tr '\\n' ' ')
      su -s /bin/sh svc -c \"FLAWROOK_CA_FILE=/ca.pem FLAWROOK_HOSTNAME=it-$name-svc \$b --interval 20s >/tmp/svc.log 2>&1 & echo \\\$! >/tmp/svc.pid\"
      i=0; until grep -q 'report sent' /tmp/svc.log 2>/dev/null || [ \$i -ge 60 ]; do i=\$((i + 1)); sleep 1; done
      echo svccaps=\$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/\$(cat /tmp/svc.pid)/status)
      echo svcsent=\$(grep -c 'report sent' /tmp/svc.log)
      kill \$(cat /tmp/svc.pid)")
  printf '%s\n' "$result" >"$OUT/nosystemd-$name.txt"
  check "install.sh exit" "$(val install)" "0"
  check "says there's no systemd" "$(val nosystemd)" "1"
  check "says cosign isn't installed, so only sha256" "$(val nocosign)" "1"
  check "the binary runs" "$(val version)" "flawrook-agent $REL"
  check "/etc/flawrook and agent.yaml: root and the flawrook group's" "$(val modes)" "750 root flawrook 640 root flawrook"
  check "the flawrook group" "$(val group)" "1"
  check "token and url in agent.yaml" "$(val config)" "2"
  check "no token in the unit" "$(val unittoken)" "0"
  case "$image" in alpine:*) want=0 ;; *) want=8 ;; esac
  check "MPL licence texts shipped" "$(val mpl)" "$want"
  check "a user outside the group can't read agent.yaml" "$(val denied)" "1"
  check "a user in the group, no capability, lists what root does" "$(val purls | cut -d' ' -f2)" "same"
  [ "$(val purls | cut -d' ' -f2)" = same ] || echo "    root $(val purls | cut -d' ' -f1), the user $(val purls | cut -d' ' -f3); first differences: $(val purldiff)"
  check "  (packages listed)" "$([ "$(val purls | cut -d' ' -f1)" -gt 0 ] && echo some)" "some"
  check "that user has no capability" "$(val svccaps)" "0000000000000000"
  check "it read the token and sent a report" "$(val svcsent)" "1"
  check "the stub got it" "$(reported "it-$name-svc" report "${T1#"${T1%????}"}")" "1"
done

echo "debian:12, a tampered deb"
result=$(docker run --rm --network "$NET" --memory 512m -v "$PWD/dist/release/install.sh:/install.sh:ro" \
  -e FLAWROOK_RELEASE_URL=http://releases:8080/tampered -e FLAWROOK_TOKEN="$T1" \
  debian:12 sh -c "apt-get update -qq >/dev/null && apt-get install -y -qq curl >/dev/null 2>&1; sh /install.sh 2>&1 | grep -c 'checksums.txt says'; dpkg -s flawrook-agent >/dev/null 2>&1; echo installed=\$?")
# shellcheck disable=SC2086 # split into words on purpose
set -- $result
check "refused with a checksum error" "$1" "1"
check "nothing installed" "$2" "installed=1"

echo "debian:12, signatures"
sig() { # release, extra env: the install's line about the signature and whether the package is there
  docker run --rm --network "$NET" --memory 512m -v "$OUT/releases/$1/install.sh:/install.sh:ro" -v "$OUT/cosign:/cosign:ro" \
    -e FLAWROOK_RELEASE_URL="http://releases:8080/$1" -e FLAWROOK_TOKEN="$T1" ${2:+-e "$2"} debian:12 sh -c "
    apt-get update -qq >/dev/null && apt-get install -y -qq curl >/dev/null 2>&1
    [ \"\${WITH_COSIGN:-}\" != 1 ] || install -m 0755 /cosign /usr/local/bin/cosign
    sh /install.sh >/tmp/out 2>&1; echo \"exit=\$? \$(dpkg -s flawrook-agent >/dev/null 2>&1 && echo installed || echo none)\"
    grep -E 'signature|cosign|checksums.txt.sig' /tmp/out | head -1"
}
result=$(sig signed WITH_COSIGN=1)
check "a good signature, cosign installed: verified and installed" "$result" "exit=0 installed
checksums.txt: signature verified (cosign)"
result=$(sig changed WITH_COSIGN=1)
check "checksums.txt changed after signing: refused, nothing installed" "$result" "exit=1 none
flawrook-agent install: checksums.txt's signature doesn't verify with the release key: not installing"
result=$(sig badsig WITH_COSIGN=1)
check "signed with another key: refused, nothing installed" "$result" "exit=1 none
flawrook-agent install: checksums.txt's signature doesn't verify with the release key: not installing"
result=$(sig nosig WITH_COSIGN=1)
check "no signature: refused, nothing installed" "$result" "exit=1 none
flawrook-agent install: the release has no checksums.txt.sig"
result=$(sig signed FLAWROOK_REQUIRE_SIGNATURE=1)
check "no cosign with FLAWROOK_REQUIRE_SIGNATURE=1: refused, nothing installed" "$result" "exit=1 none
flawrook-agent install: FLAWROOK_REQUIRE_SIGNATURE=1, but cosign isn't installed"

echo "2. systemd as PID 1"
printf 'FROM %s\nRUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv curl ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/*\nCMD ["/sbin/init"]\n' "$DEBIAN" |
  docker build -q -t flawrook-agent-test-systemd - >/dev/null
# Fake systemd versions for the floor: /fake/<name>/systemctl prints the given first line for --version and passes
# everything else to the real one. A command puts it ahead on PATH; dpkg hands that PATH to the postinstall.
for fake in "219:systemd 219" "235:systemd 235" "unreadable:systemd unknown"; do
  mkdir -p "$OUT/fake/${fake%%:*}"
  # shellcheck disable=SC2016 # the fake's own $1 and $@
  printf '#!/bin/sh\n[ "$1" = --version ] || exec /usr/bin/systemctl "$@"\necho "%s"\necho "+PAM +AUDIT +SELINUX"\n' "${fake#*:}" >"$OUT/fake/${fake%%:*}/systemctl"
  chmod 0755 "$OUT/fake/${fake%%:*}/systemctl"
done
docker run -d --rm --name "$NET-systemd" --network "$NET" --hostname it-systemd --privileged --cgroupns=host --memory 1g \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock -v "$OUT/fake:/fake:ro" \
  -v "$PWD/dist/release/install.sh:/install.sh:ro" -v "$OUT/stub/ca.pem:/ca.pem:ro" flawrook-agent-test-systemd >/dev/null
inside() { docker exec "$NET-systemd" sh -c "$1"; }
# The service's starts so far: systemd's "unit started" entries for it, by message ID, since their wording differs
# (Debian "Started flawrook-agent.service - …", Rocky "Started FlawRook agent: …"). In another container with $1.
starts() {
  sleep 2 # journald's lag
  docker exec "${1:-$NET-systemd}" sh -c "journalctl -o cat UNIT=flawrook-agent.service MESSAGE_ID=39f53479d3a045ac8e11786248231fbf --no-pager | grep -c . || true"
}
# Until boot is over: systemd-tmpfiles empties /tmp at boot ("D /tmp"), under a running install.sh.
i=0
until inside 'systemctl is-system-running 2>/dev/null' | grep -Eq '^(running|degraded)$'; do i=$((i + 1)); [ $i -lt 60 ] || { echo "systemd didn't boot"; exit 1; }; sleep 1; done

echo "two-step: agent.yaml first, then install.sh without a token"
inside "install -d -m 0700 /etc/flawrook && install -m 0600 /dev/null /etc/flawrook/agent.yaml && cp /ca.pem /etc/flawrook/ca.pem
    printf 'url: https://stub:8443\ntoken: $T1\nca_file: /etc/flawrook/ca.pem\n' >/etc/flawrook/agent.yaml
    FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >"$OUT/systemd-install.txt" 2>&1
check "started" "$(grep -c '^Started' "$OUT/systemd-install.txt")" "1"
check "started once (the journal)" "$(starts)" "1"
check "active" "$(inside 'systemctl is-active flawrook-agent')" "active"
i=0
until [ "$(reported it-systemd report "${T1#"${T1%????}"}")" -ge 1 ]; do i=$((i + 1)); [ $i -lt 100 ] || break; sleep 1; done
check "the stub got its report, with the first token" "$(reported it-systemd report "${T1#"${T1%????}"}")" "1"
pid=$(inside 'systemctl show -p MainPID --value flawrook-agent')
check "runs as its own user, not root" "$(inside "awk '/^Uid:/ { print (\$2 == 0 ? \"root\" : \"user\") }' /proc/$pid/status")" "user"
check "no capabilities" "$(inside "grep -E '^Cap(Eff|Bnd):' /proc/$pid/status | awk '{print \$2}' | tr '\n' ' '")" "0000000000000000 0000000000000000 "
check "in the flawrook group" "$(inside "gid=\$(getent group flawrook | cut -d: -f3); grep '^Groups:' /proc/$pid/status | tr '\t' ' ' | grep -c \" \$gid\\b\"")" "1"
check "its two-step agent.yaml (0600 root) given to the group" "$(inside "stat -c '%a %U %G' /etc/flawrook /etc/flawrook/agent.yaml /etc/flawrook/ca.pem | tr '\n' ' '")" "750 root flawrook 640 root flawrook 640 root flawrook "
check "a user outside the group can't read agent.yaml" "$(inside "su -s /bin/sh nobody -c 'cat /etc/flawrook/agent.yaml' 2>&1 | grep -c 'Permission denied'")" "1"
check "MemoryMax" "$(inside 'systemctl show -p MemoryMax --value flawrook-agent')" "268435456"
check "Nice, IO class and level (systemctl show)" "$(inside 'systemctl show -p Nice -p IOSchedulingClass -p IOSchedulingPriority --value flawrook-agent' | tr '\n' ' ')" "19 2 7 "
check "the running agent's nice" "$(inside "awk '{print \$19}' /proc/$pid/stat")" "19"
check "the running agent's IO priority" "$(inside "ionice -p $pid")" "best-effort: prio 7"
check "the unit's environment" "$(inside 'systemctl show -p Environment --value flawrook-agent')" "GOMEMLIMIT=96MiB FLAWROOK_SERVICE=1 HOME=/var/lib/flawrook"
check "the token never in the journal" "$(inside "journalctl -u flawrook-agent --no-pager | grep -c '$T1' || true")" "0"
check "hostIdSource" "$(grep -o '"hostIdSource":"[a-z-]*"' "$OUT/stub/requests.jsonl" | tail -1)" '"hostIdSource":"machine-id"'
inside "grep VmHWM /proc/$pid/status" >"$OUT/systemd-rss.txt"
inside 'systemd-analyze security flawrook-agent --no-pager' >"$OUT/systemd-security.txt" 2>&1 || true
echo "  $(tail -1 "$OUT/systemd-security.txt")"
echo "  $(cat "$OUT/systemd-rss.txt")"

echo "token rotation, one-line form: the package again, over the running agent"
before=$(starts) pid=$(inside 'systemctl show -p MainPID --value flawrook-agent')
inside "FLAWROOK_TOKEN=$T2 FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >>"$OUT/systemd-install.txt" 2>&1
check "started once more (the journal)" "$(($(starts) - before))" "1"
new=$(inside 'systemctl show -p MainPID --value flawrook-agent')
check "a new process" "$([ "$new" != "$pid" ] && echo yes)" "yes"
check "it runs the binary on disk, not the replaced one" "$(inside "readlink /proc/$new/exe")" "/usr/bin/flawrook-agent"
check "the new token, the url and ca_file kept" "$(inside "grep -cE '^(token: $T2|url: https://stub:8443|ca_file: /etc/flawrook/ca.pem)\$' /etc/flawrook/agent.yaml")" "3"
check "the old file kept as .bak, both the group's" "$(inside "stat -c '%a %U %G' /etc/flawrook/agent.yaml /etc/flawrook/agent.yaml.bak; grep -c '^token: $T1' /etc/flawrook/agent.yaml.bak" | tr '\n' ' ')" "640 root flawrook 640 root flawrook 1 "
i=0
until [ "$(reported it-systemd heartbeat "${T2#"${T2%????}"}")" -ge 1 ]; do i=$((i + 1)); [ $i -lt 100 ] || break; sleep 1; done
# The server already holds this host's inventory: the restarted agent's heartbeat, answered 204, is all.
check "a heartbeat with the second token, answered 204" "$(reported it-systemd heartbeat "${T2#"${T2%????}"}")" "1"
check "the same hostId" "$(grep '"hostname":"it-systemd"' "$OUT/stub/requests.jsonl" | grep -o '"hostId":"[0-9a-f]*"' | sort -u | wc -l | tr -d ' ')" "1"

echo "agent.yaml left root's alone (0600 root:root): the error names the group and the mode"
inside "chgrp root /etc/flawrook/agent.yaml && chmod 0600 /etc/flawrook/agent.yaml && systemctl restart flawrook-agent"
i=0
until inside "journalctl -u flawrook-agent --no-pager -o cat | grep -q 'needs mode 0640 root:flawrook'"; do i=$((i + 1)); [ $i -lt 30 ] || break; sleep 1; done
check "says which group and mode (the journal)" "$(inside "journalctl -u flawrook-agent --no-pager -o cat | grep -c 'member of the flawrook group: agent.yaml needs mode 0640 root:flawrook and /etc/flawrook 0750 root:flawrook'" | sed 's/^[1-9][0-9]*$/1+/')" "1+"
inside "FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >>"$OUT/systemd-install.txt" 2>&1
check "install.sh gives it back to the group" "$(inside "stat -c '%a %U %G' /etc/flawrook/agent.yaml")" "640 root flawrook"
check "active again" "$(inside 'systemctl is-active flawrook-agent')" "active"

echo "read_protected: FLAWROOK_READ_PROTECTED=1 adds CAP_DAC_READ_SEARCH, 0 takes it away"
mark=$(inside 'journalctl -u flawrook-agent --no-pager -o cat | wc -l')
inside "FLAWROOK_READ_PROTECTED=1 FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >"$OUT/systemd-read-protected.txt" 2>&1
pid=$(inside 'systemctl show -p MainPID --value flawrook-agent')
check "the drop-in" "$(inside 'cat /etc/systemd/system/flawrook-agent.service.d/read-protected.conf | grep -cE "^(AmbientCapabilities|CapabilityBoundingSet)=CAP_DAC_READ_SEARCH$"')" "2"
check "read_protected: true in agent.yaml, still the group's" "$(inside "grep -c '^read_protected: true\$' /etc/flawrook/agent.yaml; stat -c '%a %U %G' /etc/flawrook/agent.yaml" | tr '\n' ' ')" "1 640 root flawrook "
check "the agent holds CAP_DAC_READ_SEARCH" "$(inside "sed -n 's/^CapEff:[[:space:]]*//p' /proc/$pid/status")" "0000000000000004"
check "no mismatch warned" "$(inside "journalctl -u flawrook-agent --no-pager -o cat | tail -n +$((mark + 1)) | grep -c 'read_protected' || true")" "0"
inside "FLAWROOK_READ_PROTECTED=0 FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >>"$OUT/systemd-read-protected.txt" 2>&1
pid=$(inside 'systemctl show -p MainPID --value flawrook-agent')
check "0: the drop-in gone" "$(inside 'test -e /etc/systemd/system/flawrook-agent.service.d/read-protected.conf && echo there || echo gone')" "gone"
check "0: read_protected: false, no capability" "$(inside "grep -c '^read_protected: false\$' /etc/flawrook/agent.yaml; sed -n 's/^CapEff:[[:space:]]*//p' /proc/$pid/status" | tr '\n' ' ')" "1 0000000000000000 "
mark=$(inside 'journalctl -u flawrook-agent --no-pager -o cat | wc -l')
inside "sed -i 's/^read_protected: false\$/read_protected: true/' /etc/flawrook/agent.yaml && systemctl reload flawrook-agent"
i=0
until inside "journalctl -u flawrook-agent --no-pager -o cat | tail -n +$((mark + 1)) | grep -q 'read_protected is on'"; do i=$((i + 1)); [ $i -lt 20 ] || break; sleep 1; done
check "true by hand, no drop-in: warned on reload" "$(inside "journalctl -u flawrook-agent --no-pager -o cat | tail -n +$((mark + 1)) | grep -c 'read_protected is on, but the agent lacks CAP_DAC_READ_SEARCH'")" "1"
inside "sed -i 's/^read_protected: true\$/read_protected: false/' /etc/flawrook/agent.yaml && systemctl reload flawrook-agent"

echo "upgrade to $UP1 over the running agent, with that release's install.sh"
before=$(starts) pid=$(inside 'systemctl show -p MainPID --value flawrook-agent')
inside "curl -fsSL http://releases:8080/upgrade/install.sh | FLAWROOK_RELEASE_URL=http://releases:8080/upgrade sh" >"$OUT/systemd-upgrade.txt" 2>&1
check "dpkg has $UP1" "$(inside "dpkg-query -W -f '\${Version}' flawrook-agent")" "$UP1"
check "started once more (the journal)" "$(($(starts) - before))" "1"
new=$(inside 'systemctl show -p MainPID --value flawrook-agent')
check "a new process" "$([ "$new" != "$pid" ] && echo yes)" "yes"
check "it runs the binary on disk, not the replaced one" "$(inside "readlink /proc/$new/exe")" "/usr/bin/flawrook-agent"
check "active" "$(inside 'systemctl is-active flawrook-agent')" "active"

echo "systemctl reload"
inside "echo 'hostname: it-systemd-renamed' >>/etc/flawrook/agent.yaml && systemctl reload flawrook-agent"
i=0
until [ "$(reported it-systemd-renamed report)" -ge 1 ]; do i=$((i + 1)); [ $i -lt 30 ] || break; sleep 1; done
check "a report at once under the new hostname" "$(reported it-systemd-renamed report)" "1"

echo "removal"
inside 'apt-get remove -y -qq flawrook-agent >/dev/null 2>&1'
check "stopped" "$(inside 'systemctl is-active flawrook-agent || true')" "inactive"
check "agent.yaml kept until a purge" "$(inside 'test -f /etc/flawrook/agent.yaml && echo kept')" "kept"

echo "no token: purged, then installed again"
inside 'apt-get purge -y -qq flawrook-agent >/dev/null 2>&1'
check "agent.yaml gone with the purge" "$(inside 'test -f /etc/flawrook/agent.yaml || echo gone')" "gone"
before=$(starts)
inside "FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >"$OUT/systemd-no-token.txt" 2>&1
check "not started (the journal)" "$(($(starts) - before))" "0"
check "inactive" "$(inside 'systemctl is-active flawrook-agent || true')" "inactive"
check "says what comes next" "$(grep -c '^Next: write url and token to /etc/flawrook/agent.yaml' "$OUT/systemd-no-token.txt")" "1"

need="the agent needs systemd 235 or newer, so its sandbox (DynamicUser) works."
echo "systemd 219: install.sh refuses and changes nothing"
inside 'apt-get purge -y -qq flawrook-agent >/dev/null 2>&1'
before=$(starts)
inside "PATH=/fake/219:\$PATH FLAWROOK_URL=https://stub:8443 FLAWROOK_TOKEN=$T1 FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh
    echo exit=\$?" >"$OUT/systemd-219.txt" 2>&1
check "install.sh exit" "$(sed -n 's/^exit=//p' "$OUT/systemd-219.txt")" "1"
check "says why, in one line" "$(grep -v '^exit=' "$OUT/systemd-219.txt")" "flawrook-agent install: systemd 219 found; $need Not installing."
check "no package" "$(inside 'dpkg -s flawrook-agent >/dev/null 2>&1 && echo installed || echo none')" "none"
check "no unit" "$(inside 'ls /usr/lib/systemd/system/flawrook-agent.service /etc/systemd/system/flawrook-agent.service 2>/dev/null | wc -l')" "0"
check "no agent.yaml written" "$(inside 'test -e /etc/flawrook/agent.yaml && echo written || echo none')" "none"
check "not started (the journal)" "$(($(starts) - before))" "0"

echo "a systemd version it can't read: install.sh refuses too"
# Only if the case before left it installed: apt-get can't purge a package it has never heard of.
inside 'if dpkg -s flawrook-agent >/dev/null 2>&1; then apt-get purge -y -qq flawrook-agent >/dev/null 2>&1; fi'
before=$(starts)
inside "PATH=/fake/unreadable:\$PATH FLAWROOK_URL=https://stub:8443 FLAWROOK_TOKEN=$T1 FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh
    echo exit=\$?" >"$OUT/systemd-unreadable.txt" 2>&1
check "install.sh exit" "$(sed -n 's/^exit=//p' "$OUT/systemd-unreadable.txt")" "1"
check "says why, in one line" "$(grep -v '^exit=' "$OUT/systemd-unreadable.txt")" "flawrook-agent install: systemctl --version names no systemd version; $need Not installing."
check "no package" "$(inside 'dpkg -s flawrook-agent >/dev/null 2>&1 && echo installed || echo none')" "none"
check "not started (the journal)" "$(($(starts) - before))" "0"

echo "systemd 219: the deb by itself installs its files, but neither enables nor starts the service"
inside "install -d -m 0700 /etc/flawrook && install -m 0600 /dev/null /etc/flawrook/agent.yaml && cp /ca.pem /etc/flawrook/ca.pem
    printf 'url: https://stub:8443\ntoken: $T1\nca_file: /etc/flawrook/ca.pem\n' >/etc/flawrook/agent.yaml
    curl -fsS -o /tmp/flawrook-agent.deb http://releases:8080/good/flawrook-agent-$ARCH.deb"
before=$(starts)
inside "PATH=/fake/219:\$PATH dpkg -i --force-confdef --force-confold /tmp/flawrook-agent.deb >/dev/null; echo exit=\$?" >"$OUT/systemd-219-deb.txt" 2>&1
check "dpkg exit" "$(sed -n 's/^exit=//p' "$OUT/systemd-219-deb.txt")" "0"
check "installed" "$(inside "dpkg-query -W -f '\${Status} \${Version}' flawrook-agent")" "install ok installed $REL"
check "binary and unit in place" "$(inside 'ls /usr/bin/flawrook-agent /usr/lib/systemd/system/flawrook-agent.service | wc -l')" "2"
check "says why (postinstall)" "$(grep '^flawrook-agent: ' "$OUT/systemd-219-deb.txt")" "flawrook-agent: systemd 219 found; $need Installed, but not enabled or started."
check "not enabled" "$(inside 'systemctl is-enabled flawrook-agent || true')" "disabled"
check "not started (the journal)" "$(($(starts) - before))" "0"
check "inactive" "$(inside 'systemctl is-active flawrook-agent || true')" "inactive"

echo "systemd 235: install.sh installs and starts it"
inside 'apt-get purge -y -qq flawrook-agent >/dev/null 2>&1'
inside "install -d -m 0700 /etc/flawrook && install -m 0600 /dev/null /etc/flawrook/agent.yaml
    printf 'url: https://stub:8443\ntoken: $T1\nca_file: /etc/flawrook/ca.pem\n' >/etc/flawrook/agent.yaml"
before=$(starts)
inside "PATH=/fake/235:\$PATH FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh; echo exit=\$?" >"$OUT/systemd-235.txt" 2>&1
check "install.sh exit" "$(sed -n 's/^exit=//p' "$OUT/systemd-235.txt")" "0"
check "dpkg has $REL" "$(inside "dpkg-query -W -f '\${Version}' flawrook-agent")" "$REL"
check "enabled" "$(inside 'systemctl is-enabled flawrook-agent || true')" "enabled"
check "started once (the journal)" "$(($(starts) - before))" "1"
check "active" "$(inside 'systemctl is-active flawrook-agent || true')" "active"

echo "a systemd that ignores DynamicUser= (a drop-in): the agent refuses to run as root, and isn't restarted"
refusal="running as root under systemd: this systemd ignored DynamicUser=. Use systemd 235 or newer, or run the agent as a non-root user without systemd. Not started."
dropin=/etc/systemd/system/flawrook-agent.service.d/old-systemd.conf
# DynamicUser=no is what a systemd before 232 makes of DynamicUser=yes. Such a systemd sets no INVOCATION_ID either:
# UnsetEnvironment= drops it here, so the unit's FLAWROOK_SERVICE alone tells the agent.
inside "mkdir -p ${dropin%/*} && printf '[Service]\nDynamicUser=no\nUnsetEnvironment=INVOCATION_ID\n' >$dropin
    systemctl daemon-reload && systemctl restart flawrook-agent"
i=0
until [ "$(inside 'systemctl show -p ActiveState --value flawrook-agent')" != active ]; do i=$((i + 1)); [ $i -lt 15 ] || break; sleep 1; done
check "exit status 78" "$(inside 'systemctl show -p ExecMainStatus --value flawrook-agent')" "78"
# Restart=on-failure would show activating/auto-restart for RestartSec; failed/failed means none is coming.
check "failed, no restart coming" "$(inside 'systemctl show -p ActiveState -p SubState -p Result -p NRestarts flawrook-agent' | sort | tr '\n' ' ')" \
  "ActiveState=failed NRestarts=0 Result=exit-code SubState=failed "
check "says why and how out (the journal)" "$(inside "journalctl -u flawrook-agent --no-pager -o cat | grep -cF '$refusal'")" "1"

echo "as root with the unit's marker or INVOCATION_ID, by hand"
check "--version answers" "$(inside 'FLAWROOK_SERVICE=1 /usr/bin/flawrook-agent --version | cut -d" " -f1-2')" "flawrook-agent $REL"
check "--dry-run refuses (the marker)" "$(inside 'FLAWROOK_SERVICE=1 /usr/bin/flawrook-agent --dry-run >/dev/null 2>&1; echo $?')" "78"
check "--dry-run refuses (INVOCATION_ID)" "$(inside 'INVOCATION_ID=52ebaf0c5b1547d69e2516d2a193cbe5 /usr/bin/flawrook-agent --dry-run >/dev/null 2>&1; echo $?')" "78"
check "--dry-run as root with neither runs" "$(inside 'env -u FLAWROOK_SERVICE -u INVOCATION_ID /usr/bin/flawrook-agent --dry-run >/dev/null 2>&1; echo $?')" "0"

echo "the drop-in removed: it starts as its own user again"
inside "rm $dropin && systemctl daemon-reload && systemctl restart flawrook-agent"
check "active" "$(inside 'systemctl is-active flawrook-agent || true')" "active"
pid=$(inside 'systemctl show -p MainPID --value flawrook-agent')
check "runs as its own user, not root" "$(inside "awk '/^Uid:/ { print (\$2 == 0 ? \"root\" : \"user\") }' /proc/$pid/status")" "user"

echo "an upgrade from 0.1.0 as released: its modes (0700, 0600) and its capability, then this release's install.sh"
docker run -d --rm --name "$NET-from010" --network "$NET" --hostname it-from010 --privileged --cgroupns=host --memory 1g \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v "$PWD/dist/release/install.sh:/install.sh:ro" -v "$OUT/stub/ca.pem:/ca.pem:ro" flawrook-agent-test-systemd >/dev/null
old() { docker exec "$NET-from010" sh -c "$1"; }
i=0
until old 'systemctl is-system-running 2>/dev/null' | grep -Eq '^(running|degraded)$'; do i=$((i + 1)); [ $i -lt 60 ] || { echo "systemd didn't boot"; exit 1; }; sleep 1; done
old "install -d -m 0700 /etc/flawrook && install -m 0600 /dev/null /etc/flawrook/agent.yaml && install -m 0600 /ca.pem /etc/flawrook/ca.pem
    printf 'url: https://stub:8443\ntoken: $T1\nca_file: /etc/flawrook/ca.pem\n' >/etc/flawrook/agent.yaml
    curl -fsSL http://releases:8080/v010/install.sh | FLAWROOK_RELEASE_URL=http://releases:8080/v010 sh" >"$OUT/from010-install.txt" 2>&1
pid=$(old 'systemctl show -p MainPID --value flawrook-agent')
check "0.1.0 runs, with its capability" "$(old "flawrook-agent --version | cut -d' ' -f2; sed -n 's/^CapEff:[[:space:]]*//p' /proc/$pid/status" | tr '\n' ' ')" "0.1.0 0000000000000004 "
check "0.1.0's modes" "$(old "stat -c '%a %U %G' /etc/flawrook /etc/flawrook/agent.yaml" | tr '\n' ' ')" "700 root root 600 root root "
i=0
until [ "$(reported it-from010 report "${T1#"${T1%????}"}")" -ge 1 ]; do i=$((i + 1)); [ $i -lt 100 ] || break; sleep 1; done
check "0.1.0 reported" "$(reported it-from010 report "${T1#"${T1%????}"}")" "1"
old "FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >"$OUT/from010-upgrade.txt" 2>&1
pid=$(old 'systemctl show -p MainPID --value flawrook-agent')
check "upgraded" "$(old "dpkg-query -W -f '\${Version}' flawrook-agent")" "$REL"
check "the modes now root and the flawrook group's" "$(old "stat -c '%a %U %G' /etc/flawrook /etc/flawrook/agent.yaml /etc/flawrook/ca.pem" | tr '\n' ' ')" "750 root flawrook 640 root flawrook 640 root flawrook "
check "no capability" "$(old "sed -n 's/^CapEff:[[:space:]]*//p' /proc/$pid/status")" "0000000000000000"
# The agent's version is in the report's hash, so the upgraded agent sends a report, not a heartbeat.
i=0
until [ "$(reported it-from010 report "${T1#"${T1%????}"}")" -ge 2 ]; do i=$((i + 1)); [ $i -lt 100 ] || break; sleep 1; done
check "it read the token and reported again" "$(reported it-from010 report "${T1#"${T1%????}"}")" "2"
docker stop -t 2 "$NET-from010" >/dev/null

echo "an upgrade from 0.2.0 as released: the flawrook group's modes, no capability, then this release's install.sh"
docker run -d --rm --name "$NET-from020" --network "$NET" --hostname it-from020 --privileged --cgroupns=host --memory 1g \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v "$PWD/dist/release/install.sh:/install.sh:ro" -v "$OUT/stub/ca.pem:/ca.pem:ro" flawrook-agent-test-systemd >/dev/null
was020() { docker exec "$NET-from020" sh -c "$1"; }
i=0
until was020 'systemctl is-system-running 2>/dev/null' | grep -Eq '^(running|degraded)$'; do i=$((i + 1)); [ $i -lt 60 ] || { echo "systemd didn't boot"; exit 1; }; sleep 1; done
was020 "install -d -m 0700 /etc/flawrook && install -m 0600 /dev/null /etc/flawrook/agent.yaml && install -m 0600 /ca.pem /etc/flawrook/ca.pem
    printf 'url: https://stub:8443\ntoken: $T1\nca_file: /etc/flawrook/ca.pem\n' >/etc/flawrook/agent.yaml
    curl -fsSL http://releases:8080/v020/install.sh | FLAWROOK_RELEASE_URL=http://releases:8080/v020 sh" >"$OUT/from020-install.txt" 2>&1
pid=$(was020 'systemctl show -p MainPID --value flawrook-agent')
check "0.2.0 runs, with no capability" "$(was020 "flawrook-agent --version | cut -d' ' -f2; sed -n 's/^CapEff:[[:space:]]*//p' /proc/$pid/status" | tr '\n' ' ')" "0.2.0 0000000000000000 "
check "0.2.0's modes" "$(was020 "stat -c '%a %U %G' /etc/flawrook /etc/flawrook/agent.yaml /etc/flawrook/ca.pem" | tr '\n' ' ')" "750 root flawrook 640 root flawrook 640 root flawrook "
i=0
until [ "$(reported it-from020 report "${T1#"${T1%????}"}")" -ge 1 ]; do i=$((i + 1)); [ $i -lt 100 ] || break; sleep 1; done
check "0.2.0 reported" "$(reported it-from020 report "${T1#"${T1%????}"}")" "1"
before=$(starts "$NET-from020")
was020 "FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >"$OUT/from020-upgrade.txt" 2>&1
pid=$(was020 'systemctl show -p MainPID --value flawrook-agent')
check "upgraded" "$(was020 "dpkg-query -W -f '\${Version}' flawrook-agent")" "$REL"
check "started once more (the journal)" "$(($(starts "$NET-from020") - before))" "1"
check "the modes kept" "$(was020 "stat -c '%a %U %G' /etc/flawrook /etc/flawrook/agent.yaml /etc/flawrook/ca.pem" | tr '\n' ' ')" "750 root flawrook 640 root flawrook 640 root flawrook "
check "no capability" "$(was020 "sed -n 's/^CapEff:[[:space:]]*//p' /proc/$pid/status")" "0000000000000000"
# The agent's version is in the report's hash, so the upgraded agent sends a report, not a heartbeat.
i=0
until [ "$(reported it-from020 report "${T1#"${T1%????}"}")" -ge 2 ]; do i=$((i + 1)); [ $i -lt 100 ] || break; sleep 1; done
check "it read the token and reported again" "$(reported it-from020 report "${T1#"${T1%????}"}")" "2"
docker stop -t 2 "$NET-from020" >/dev/null

echo "systemd 219 installed but not running (a chroot, an image build)"
result=$(docker run --rm --network "$NET" --memory 512m -v "$OUT/fake:/fake:ro" -v "$PWD/dist/release/install.sh:/install.sh:ro" \
  flawrook-agent-test-systemd sh -c "test -d /run/systemd/system && echo running || echo not-running
    PATH=/fake/219:\$PATH FLAWROOK_URL=https://stub:8443 FLAWROOK_TOKEN=$T1 FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh >/tmp/out 2>&1
    echo install=\$?; grep -c 'systemd 219 found' /tmp/out; dpkg -s flawrook-agent >/dev/null 2>&1; echo installed=\$?
    install -d -m 0700 /etc/flawrook && printf 'url: https://stub:8443\ntoken: $T1\n' >/etc/flawrook/agent.yaml && chmod 0600 /etc/flawrook/agent.yaml
    curl -fsS -o /tmp/flawrook-agent.deb http://releases:8080/good/flawrook-agent-$ARCH.deb
    PATH=/fake/219:\$PATH dpkg -i --force-confdef --force-confold /tmp/flawrook-agent.deb >/dev/null 2>&1; echo dpkg=\$?
    ls /etc/systemd/system/*.wants/flawrook-agent.service 2>/dev/null | wc -l")
# shellcheck disable=SC2086 # split into words on purpose
set -- $result
check "systemd isn't running" "$1" "not-running"
check "install.sh refuses" "$2 $3" "install=1 1"
check "no package" "$4" "installed=1"
check "the deb by itself installs" "$5" "dpkg=0"
check "and enables nothing" "$6" "0"

echo "3. systemd as PID 1, rpm"
printf 'FROM %s\nRUN dnf install -y -q systemd >/dev/null && dnf clean all >/dev/null\nCMD ["/usr/sbin/init"]\n' "$ROCKY" |
  docker build -q -t flawrook-agent-test-rocky-systemd - >/dev/null
docker run -d --rm --name "$NET-rocky" --network "$NET" --hostname it-rocky --privileged --cgroupns=host --memory 1g \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v "$PWD/dist/release/install.sh:/install.sh:ro" -v "$OUT/stub/ca.pem:/ca.pem:ro" flawrook-agent-test-rocky-systemd >/dev/null
rocky() { docker exec "$NET-rocky" sh -c "$1"; }
i=0
until rocky 'systemctl is-system-running 2>/dev/null' | grep -Eq '^(running|degraded)$'; do i=$((i + 1)); [ $i -lt 60 ] || { echo "systemd didn't boot"; exit 1; }; sleep 1; done

echo "fresh install with a token (two-step)"
rocky "install -d -m 0700 /etc/flawrook && install -m 0600 /dev/null /etc/flawrook/agent.yaml && cp /ca.pem /etc/flawrook/ca.pem
    printf 'url: https://stub:8443\ntoken: $T1\nca_file: /etc/flawrook/ca.pem\n' >/etc/flawrook/agent.yaml
    FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >"$OUT/rocky-install.txt" 2>&1
check "rpm has $REL" "$(rocky "rpm -q --qf '%{VERSION}' flawrook-agent")" "$REL"
check "started once (the journal)" "$(starts "$NET-rocky")" "1"
check "active" "$(rocky 'systemctl is-active flawrook-agent')" "active"
pid=$(rocky 'systemctl show -p MainPID --value flawrook-agent')
check "no capability, in the flawrook group" "$(rocky "sed -n 's/^CapEff:[[:space:]]*//p' /proc/$pid/status; gid=\$(getent group flawrook | cut -d: -f3); grep '^Groups:' /proc/$pid/status | tr '\t' ' ' | grep -c \" \$gid\\b\"" | tr '\n' ' ')" "0000000000000000 1 "
check "the modes" "$(rocky "stat -c '%a %U %G' /etc/flawrook /etc/flawrook/agent.yaml" | tr '\n' ' ')" "750 root flawrook 640 root flawrook "
i=0
until [ "$(reported it-rocky report "${T1#"${T1%????}"}")" -ge 1 ]; do i=$((i + 1)); [ $i -lt 100 ] || break; sleep 1; done
check "it read the token and reported" "$(reported it-rocky report "${T1#"${T1%????}"}")" "1"

echo "upgrade to $UP1 over the running agent, with that release's install.sh"
before=$(starts "$NET-rocky") pid=$(rocky 'systemctl show -p MainPID --value flawrook-agent')
rocky "curl -fsSL http://releases:8080/upgrade/install.sh | FLAWROOK_RELEASE_URL=http://releases:8080/upgrade sh" >"$OUT/rocky-upgrade.txt" 2>&1
check "rpm has $UP1" "$(rocky "rpm -q --qf '%{VERSION}' flawrook-agent")" "$UP1"
check "started once more (the journal)" "$(($(starts "$NET-rocky") - before))" "1"
new=$(rocky 'systemctl show -p MainPID --value flawrook-agent')
check "a new process" "$([ "$new" != "$pid" ] && echo yes)" "yes"
# install.sh starts a service that isn't running, so here a stop by the old %preun shows as a second start.
check "active" "$(rocky 'systemctl is-active flawrook-agent')" "active"
check "it runs the binary on disk, not the replaced one" "$(rocky "readlink /proc/$new/exe")" "/usr/bin/flawrook-agent"

echo "upgrade to $UP2 by rpm alone, as dnf would"
before=$(starts "$NET-rocky") pid=$(rocky 'systemctl show -p MainPID --value flawrook-agent')
rocky "cd /tmp && curl -fsSLO http://releases:8080/direct/flawrook-agent-$UP2-$RPMARCH.rpm && rpm -U flawrook-agent-$UP2-$RPMARCH.rpm" >"$OUT/rocky-rpm-upgrade.txt" 2>&1
check "rpm has $UP2" "$(rocky "rpm -q --qf '%{VERSION}' flawrook-agent")" "$UP2"
check "started once more (the journal)" "$(($(starts "$NET-rocky") - before))" "1"
new=$(rocky 'systemctl show -p MainPID --value flawrook-agent')
check "a new process" "$([ "$new" != "$pid" ] && echo yes)" "yes"
check "active right after the transaction (the old %preun didn't stop it)" "$(rocky 'systemctl is-active flawrook-agent || true')" "active"
check "still enabled" "$(rocky 'systemctl is-enabled flawrook-agent || true')" "enabled"
check "it runs the binary on disk, not the replaced one" "$(rocky "readlink /proc/$new/exe || true")" "/usr/bin/flawrook-agent"

echo "4. systemd 237 as PID 1 (ubuntu:18.04), the oldest the floor takes"
docker image inspect ubuntu:18.04 >/dev/null 2>&1 || docker pull -q ubuntu:18.04 >/dev/null
BIONIC=ubuntu:18.04@sha256:$(docker image inspect ubuntu:18.04 --format '{{index .RepoDigests 0}}' | cut -d: -f2)
# No console logins: a container never gets the serial console (hvc0) the getty would wait 90 s for.
printf 'FROM %s\nRUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv curl ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/* && systemctl mask getty.target serial-getty@.service >/dev/null 2>&1\nCMD ["/sbin/init"]\n' "$BIONIC" |
  docker build -q -t flawrook-agent-test-bionic-systemd - >/dev/null
docker run -d --rm --name "$NET-bionic" --network "$NET" --hostname it-bionic --privileged --cgroupns=host --memory 1g \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v "$PWD/dist/release/install.sh:/install.sh:ro" -v "$OUT/stub/ca.pem:/ca.pem:ro" flawrook-agent-test-bionic-systemd >/dev/null
bionic() { docker exec "$NET-bionic" sh -c "$1"; }
i=0
until bionic 'systemctl is-system-running 2>/dev/null' | grep -Eq '^(running|degraded)$'; do i=$((i + 1)); [ $i -lt 60 ] || { echo "systemd didn't boot"; exit 1; }; sleep 1; done
check "systemd 237" "$(bionic 'systemctl --version | head -1 | cut -d" " -f1-2')" "systemd 237"
bionic "install -d -m 0700 /etc/flawrook && install -m 0600 /dev/null /etc/flawrook/agent.yaml && cp /ca.pem /etc/flawrook/ca.pem
    printf 'url: https://stub:8443\ntoken: $T1\nca_file: /etc/flawrook/ca.pem\n' >/etc/flawrook/agent.yaml
    FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >"$OUT/bionic-install.txt" 2>&1
i=0
until [ "$(reported it-bionic report "${T1#"${T1%????}"}")" -ge 1 ]; do i=$((i + 1)); [ $i -lt 100 ] || break; sleep 1; done
bionic 'systemctl status flawrook-agent --no-pager; journalctl -u flawrook-agent --no-pager -o cat' >"$OUT/bionic-service.txt" 2>&1 || true
check "it reported (no SIGSYS from SystemCallFilter)" "$(reported it-bionic report "${T1#"${T1%????}"}")" "1"
check "systemd 237 knew every set and call but @system-service" "$(grep -c 'system call' "$OUT/bionic-service.txt" | sed 's/^0$/none/')" "$(grep -c 'Unknown system call group, ignoring: @system-service$' "$OUT/bionic-service.txt" | sed 's/^0$/none/')"
check "active" "$(bionic 'systemctl is-active flawrook-agent || true')" "active"
echo "  systemd 237, beyond the first report: heartbeats, a reload, a token rotation (the stub by name, through Go's resolver)"
# A test-only drop-in shortens the cycle, so a heartbeat comes within the test.
bionic "mkdir -p /etc/systemd/system/flawrook-agent.service.d && printf '[Service]\nExecStart=\nExecStart=/usr/bin/flawrook-agent --interval 20s\n' >/etc/systemd/system/flawrook-agent.service.d/test-interval.conf
    systemctl daemon-reload && systemctl restart flawrook-agent"
i=0
until [ "$(reported it-bionic heartbeat "${T1#"${T1%????}"}")" -ge 2 ]; do i=$((i + 1)); [ $i -lt 90 ] || break; sleep 1; done
check "heartbeats, answered" "$([ "$(reported it-bionic heartbeat "${T1#"${T1%????}"}")" -ge 2 ] && echo yes)" "yes"
pid=$(bionic 'systemctl show -p MainPID --value flawrook-agent')
bionic 'systemctl reload flawrook-agent'
sleep 25
check "alive after a reload, the same process" "$(bionic 'systemctl show -p MainPID --value flawrook-agent')" "$pid"
bionic "FLAWROOK_TOKEN=$T2 FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >>"$OUT/bionic-install.txt" 2>&1
i=0
until [ "$(reported it-bionic heartbeat "${T2#"${T2%????}"}")" -ge 1 ] || [ "$(reported it-bionic report "${T2#"${T2%????}"}")" -ge 1 ]; do i=$((i + 1)); [ $i -lt 90 ] || break; sleep 1; done
check "the rotated token used (a heartbeat or a report)" "$([ "$(reported it-bionic heartbeat "${T2#"${T2%????}"}")" -ge 1 ] || [ "$(reported it-bionic report "${T2#"${T2%????}"}")" -ge 1 ] && echo yes)" "yes"
check "active through it all" "$(bionic 'systemctl is-active flawrook-agent || true')" "active"
check "no SIGSYS in the journal" "$(bionic 'journalctl -u flawrook-agent --no-pager -o cat | grep -c "status=31/SYS" || true')" "0"
bionic 'systemctl status flawrook-agent --no-pager; journalctl -u flawrook-agent --no-pager -o cat' >"$OUT/bionic-service.txt" 2>&1 || true
# What systemd 237 made of the unit, for the README's table: the lines it didn't know, ignored.
bionic 'journalctl --no-pager -o cat | grep "flawrook-agent.service" | grep -i "unknown\|ignoring" || true' >"$OUT/bionic-ignored.txt"
echo "  systemd 237 ignored: $(grep -c . "$OUT/bionic-ignored.txt") line(s), in bionic-ignored.txt"
exit $fail
