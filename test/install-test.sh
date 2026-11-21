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
#    on alpine:3.20. The files, their modes, the token only in agent.yaml. A tampered deb is refused.
# 2. systemd as PID 1 (debian:12 plus systemd, built here, privileged): the two-step form starts the
#    service, which reports to the stub as its own user with CAP_DAC_READ_SEARCH only; a token rotation
#    with the one-line form keeps the other keys; systemctl reload rereads the config; removal stops it.
#    The service starts exactly once per install (the journal's count): a fresh install with a token, the
#    same package again over the running agent, an upgrade to 0.1.1 (the same binary, repacked), and none at
#    all without a token. The systemd floor, with a fake systemctl --version: on 219, or a version it can't
#    read, install.sh refuses and changes nothing; on 219 the deb by itself installs its files but neither
#    enables nor starts the service; on 235 install.sh installs and starts it. With systemd 219 installed but
#    not running, install.sh refuses as well, and the deb by itself enables nothing. A systemd that ignores
#    DynamicUser= (a drop-in) starts the agent as root: it refuses with exit status 78, which isn't restarted;
#    as root with the unit's marker --version still answers and --dry-run refuses.
# 3. systemd as PID 1 with rpm (rockylinux:9 plus systemd, built here, privileged): a fresh install with a token
#    starts it once; the upgrade to 0.1.1 with install.sh, and to 0.1.2 by rpm alone, each start it once more
#    and leave it running: rpm runs the new package's %post before the old one's %preun, which must not stop
#    what %post started.
# Usage: test/install-test.sh [out-dir]
# PREBUILT=1 uses dist/stub-linux-<arch> as it is, without building.
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
sed "s/@VERSION@/$(sed -n 's/^VERSION=//p' dist/release/install.sh)/" packaging/install.sh | cmp -s - dist/release/install.sh ||
  { echo "dist/release/install.sh is older than packaging/install.sh: run scripts/release.sh"; exit 1; }
rm -rf "$OUT"
mkdir -p "$OUT/stub" "$OUT/releases"
cp -Rc dist/release "$OUT/releases/good" 2>/dev/null || cp -R dist/release "$OUT/releases/good"
cp -R "$OUT/releases/good" "$OUT/releases/tampered"
printf x >>"$OUT/releases/tampered/flawrook-agent-$ARCH.deb"
# Upgrades: the same binary as a 0.1.1 deb and rpm, with its install.sh and checksums.txt, as release.sh makes them;
# and as a 0.1.2 rpm, for an upgrade by rpm alone.
mkdir -p "$OUT/upgrade-src/dist/pkg" "$OUT/releases/direct"
cp -R packaging LICENSE NOTICE third_party "$OUT/upgrade-src/"
# No Go file in the output: under dist/gate/ it would be a package of the module's next `go test ./...`.
rm -f "$OUT/upgrade-src/packaging/"*_test.go
cp "dist/release/flawrook-agent-linux-$ARCH" "$OUT/upgrade-src/dist/pkg/flawrook-agent"
case $ARCH in arm64) RPMARCH=aarch64 ;; *) RPMARCH=x86_64 ;; esac
repack() { # version, deb or rpm, file name
  # shellcheck disable=SC2016 # sed matches release.sh's literal ${MAINTAINER:=…}
  docker run --rm --label org.flawrook.agent=build -v "$OUT/upgrade-src":/src -w /src -e VERSION="$1" -e GOARCH="$ARCH" \
    -e MAINTAINER="$(sed -n 's/^: "${MAINTAINER:=\(.*\)}".*/\1/p' scripts/release.sh)" "$(sed -n 's/^NFPM_IMAGE=//p' scripts/release.sh)" \
    package --config packaging/nfpm.yaml --packager "$2" --target "dist/$3" >/dev/null
}
repack 0.1.1 deb "flawrook-agent-$ARCH.deb"
repack 0.1.1 rpm "flawrook-agent-$RPMARCH.rpm"
repack 0.1.2 rpm "flawrook-agent-0.1.2-$RPMARCH.rpm"
cp -R "$OUT/releases/good" "$OUT/releases/upgrade"
cp "$OUT/upgrade-src/dist/flawrook-agent-$ARCH.deb" "$OUT/upgrade-src/dist/flawrook-agent-$RPMARCH.rpm" "$OUT/releases/upgrade/"
cp "$OUT/upgrade-src/dist/flawrook-agent-0.1.2-$RPMARCH.rpm" "$OUT/releases/direct/"
sed "s/@VERSION@/0.1.1/" packaging/install.sh >"$OUT/releases/upgrade/install.sh"
(cd "$OUT/releases/upgrade" && for f in *; do [ "$f" = checksums.txt ] || printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"; done >../upgrade-checksums.txt)
mv "$OUT/releases/upgrade-checksums.txt" "$OUT/releases/upgrade/checksums.txt"
if [ "${PREBUILT:-}" = 1 ]; then # the stub from an earlier build, so a run on a busy machine compiles nothing
  [ -x "dist/stub-linux-$ARCH" ] || { echo "PREBUILT=1, but dist/stub-linux-$ARCH isn't built" >&2; exit 1; }
else
  GOARCH=$ARCH scripts/docker-go.sh build -o "dist/stub-linux-$ARCH" ./test/stub
fi

# shellcheck disable=SC2317 # run by the trap
cleanup() {
  docker stop -t 2 "$NET-stub" "$NET-systemd" "$NET-rocky" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create "$NET" >/dev/null
docker run -d --rm --name "$NET-stub" --network "$NET" --network-alias stub --network-alias releases \
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
for image in debian:12 ubuntu:24.04 rockylinux:9 alpine:3.20; do
  echo "$image"
  prep=true
  case "$image" in debian:* | ubuntu:*) prep="apt-get update -qq >/dev/null && apt-get install -y -qq curl >/dev/null 2>&1" ;; esac
  result=$(docker run --rm --network "$NET" -v "$PWD/dist/release/install.sh:/install.sh:ro" \
    -e FLAWROOK_RELEASE_URL=http://releases:8080/good -e FLAWROOK_URL=https://stub:8443 -e FLAWROOK_TOKEN="$T1" \
    "$image" sh -c "$prep && sh /install.sh >/tmp/out 2>&1; echo install=\$?
      grep -c 'No systemd here' /tmp/out
      b=\$(command -v flawrook-agent); \$b --version | cut -d' ' -f1-2
      stat -c '%a %U' /etc/flawrook /etc/flawrook/agent.yaml | tr '\n' ' '; echo
      grep -c '^token: $T1\$' /etc/flawrook/agent.yaml; grep -c '^url: https://stub:8443\$' /etc/flawrook/agent.yaml
      cat /usr/lib/systemd/system/flawrook-agent.service 2>/dev/null | grep -c flra_ || true
      ls /usr/share/doc/flawrook-agent/third_party/licenses/github.com/hashicorp 2>/dev/null | wc -l")
  # shellcheck disable=SC2086 # split into words on purpose
  set -- $result
  check "install.sh exit" "$1" "install=0"
  check "says there's no systemd" "$2" "1"
  check "the binary runs" "$3 $4" "flawrook-agent 0.1.0"
  check "/etc/flawrook and agent.yaml modes" "$5 $6 $7 $8" "700 root 600 root"
  check "token and url in agent.yaml" "$9 ${10}" "1 1"
  check "no token in the unit" "${11}" "0"
  case "$image" in alpine:*) want=0 ;; *) want=8 ;; esac
  check "MPL licence texts shipped" "${12}" "$want"
done

echo "debian:12, a tampered deb"
result=$(docker run --rm --network "$NET" -v "$PWD/dist/release/install.sh:/install.sh:ro" \
  -e FLAWROOK_RELEASE_URL=http://releases:8080/tampered -e FLAWROOK_TOKEN="$T1" \
  debian:12 sh -c "apt-get update -qq >/dev/null && apt-get install -y -qq curl >/dev/null 2>&1; sh /install.sh 2>&1 | grep -c 'checksums.txt says'; dpkg -s flawrook-agent >/dev/null 2>&1; echo installed=\$?")
# shellcheck disable=SC2086 # split into words on purpose
set -- $result
check "refused with a checksum error" "$1" "1"
check "nothing installed" "$2" "installed=1"

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
docker run -d --rm --name "$NET-systemd" --network "$NET" --hostname it-systemd --privileged --cgroupns=host \
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
check "capabilities (CAP_DAC_READ_SEARCH only)" "$(inside "grep -E '^Cap(Eff|Bnd):' /proc/$pid/status | awk '{print \$2}' | tr '\n' ' '")" "0000000000000004 0000000000000004 "
check "MemoryMax" "$(inside 'systemctl show -p MemoryMax --value flawrook-agent')" "268435456"
check "Nice, IO class and level (systemctl show)" "$(inside 'systemctl show -p Nice -p IOSchedulingClass -p IOSchedulingPriority --value flawrook-agent' | tr '\n' ' ')" "19 2 7 "
check "the running agent's nice" "$(inside "awk '{print \$19}' /proc/$pid/stat")" "19"
check "the running agent's IO priority" "$(inside "ionice -p $pid")" "best-effort: prio 7"
check "the unit's environment" "$(inside 'systemctl show -p Environment --value flawrook-agent')" "GOMEMLIMIT=96MiB FLAWROOK_SERVICE=1"
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
check "the old file kept as .bak, 0600" "$(inside "stat -c %a /etc/flawrook/agent.yaml.bak; grep -c '^token: $T1' /etc/flawrook/agent.yaml.bak" | tr '\n' ' ')" "600 1 "
i=0
until [ "$(reported it-systemd heartbeat "${T2#"${T2%????}"}")" -ge 1 ]; do i=$((i + 1)); [ $i -lt 100 ] || break; sleep 1; done
# The server already holds this host's inventory: the restarted agent's heartbeat, answered 204, is all.
check "a heartbeat with the second token, answered 204" "$(reported it-systemd heartbeat "${T2#"${T2%????}"}")" "1"
check "the same hostId" "$(grep '"hostname":"it-systemd"' "$OUT/stub/requests.jsonl" | grep -o '"hostId":"[0-9a-f]*"' | sort -u | wc -l | tr -d ' ')" "1"

echo "upgrade to 0.1.1 over the running agent, with that release's install.sh"
before=$(starts) pid=$(inside 'systemctl show -p MainPID --value flawrook-agent')
inside "curl -fsSL http://releases:8080/upgrade/install.sh | FLAWROOK_RELEASE_URL=http://releases:8080/upgrade sh" >"$OUT/systemd-upgrade.txt" 2>&1
check "dpkg has 0.1.1" "$(inside "dpkg-query -W -f '\${Version}' flawrook-agent")" "0.1.1"
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
check "installed" "$(inside "dpkg-query -W -f '\${Status} \${Version}' flawrook-agent")" "install ok installed 0.1.0"
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
check "dpkg has 0.1.0" "$(inside "dpkg-query -W -f '\${Version}' flawrook-agent")" "0.1.0"
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
check "--version answers" "$(inside 'FLAWROOK_SERVICE=1 /usr/bin/flawrook-agent --version | cut -d" " -f1-2')" "flawrook-agent 0.1.0"
check "--dry-run refuses (the marker)" "$(inside 'FLAWROOK_SERVICE=1 /usr/bin/flawrook-agent --dry-run >/dev/null 2>&1; echo $?')" "78"
check "--dry-run refuses (INVOCATION_ID)" "$(inside 'INVOCATION_ID=52ebaf0c5b1547d69e2516d2a193cbe5 /usr/bin/flawrook-agent --dry-run >/dev/null 2>&1; echo $?')" "78"
check "--dry-run as root with neither runs" "$(inside 'env -u FLAWROOK_SERVICE -u INVOCATION_ID /usr/bin/flawrook-agent --dry-run >/dev/null 2>&1; echo $?')" "0"

echo "the drop-in removed: it starts as its own user again"
inside "rm $dropin && systemctl daemon-reload && systemctl restart flawrook-agent"
check "active" "$(inside 'systemctl is-active flawrook-agent || true')" "active"
pid=$(inside 'systemctl show -p MainPID --value flawrook-agent')
check "runs as its own user, not root" "$(inside "awk '/^Uid:/ { print (\$2 == 0 ? \"root\" : \"user\") }' /proc/$pid/status")" "user"

echo "systemd 219 installed but not running (a chroot, an image build)"
result=$(docker run --rm --network "$NET" -v "$OUT/fake:/fake:ro" -v "$PWD/dist/release/install.sh:/install.sh:ro" \
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
docker run -d --rm --name "$NET-rocky" --network "$NET" --hostname it-rocky --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v "$PWD/dist/release/install.sh:/install.sh:ro" -v "$OUT/stub/ca.pem:/ca.pem:ro" flawrook-agent-test-rocky-systemd >/dev/null
rocky() { docker exec "$NET-rocky" sh -c "$1"; }
i=0
until rocky 'systemctl is-system-running 2>/dev/null' | grep -Eq '^(running|degraded)$'; do i=$((i + 1)); [ $i -lt 60 ] || { echo "systemd didn't boot"; exit 1; }; sleep 1; done

echo "fresh install with a token (two-step)"
rocky "install -d -m 0700 /etc/flawrook && install -m 0600 /dev/null /etc/flawrook/agent.yaml && cp /ca.pem /etc/flawrook/ca.pem
    printf 'url: https://stub:8443\ntoken: $T1\nca_file: /etc/flawrook/ca.pem\n' >/etc/flawrook/agent.yaml
    FLAWROOK_RELEASE_URL=http://releases:8080/good sh /install.sh" >"$OUT/rocky-install.txt" 2>&1
check "rpm has 0.1.0" "$(rocky "rpm -q --qf '%{VERSION}' flawrook-agent")" "0.1.0"
check "started once (the journal)" "$(starts "$NET-rocky")" "1"
check "active" "$(rocky 'systemctl is-active flawrook-agent')" "active"

echo "upgrade to 0.1.1 over the running agent, with that release's install.sh"
before=$(starts "$NET-rocky") pid=$(rocky 'systemctl show -p MainPID --value flawrook-agent')
rocky "curl -fsSL http://releases:8080/upgrade/install.sh | FLAWROOK_RELEASE_URL=http://releases:8080/upgrade sh" >"$OUT/rocky-upgrade.txt" 2>&1
check "rpm has 0.1.1" "$(rocky "rpm -q --qf '%{VERSION}' flawrook-agent")" "0.1.1"
check "started once more (the journal)" "$(($(starts "$NET-rocky") - before))" "1"
new=$(rocky 'systemctl show -p MainPID --value flawrook-agent')
check "a new process" "$([ "$new" != "$pid" ] && echo yes)" "yes"
# install.sh starts a service that isn't running, so here a stop by the old %preun shows as a second start.
check "active" "$(rocky 'systemctl is-active flawrook-agent')" "active"
check "it runs the binary on disk, not the replaced one" "$(rocky "readlink /proc/$new/exe")" "/usr/bin/flawrook-agent"

echo "upgrade to 0.1.2 by rpm alone, as dnf would"
before=$(starts "$NET-rocky") pid=$(rocky 'systemctl show -p MainPID --value flawrook-agent')
rocky "cd /tmp && curl -fsSLO http://releases:8080/direct/flawrook-agent-0.1.2-$RPMARCH.rpm && rpm -U flawrook-agent-0.1.2-$RPMARCH.rpm" >"$OUT/rocky-rpm-upgrade.txt" 2>&1
check "rpm has 0.1.2" "$(rocky "rpm -q --qf '%{VERSION}' flawrook-agent")" "0.1.2"
check "started once more (the journal)" "$(($(starts "$NET-rocky") - before))" "1"
new=$(rocky 'systemctl show -p MainPID --value flawrook-agent')
check "a new process" "$([ "$new" != "$pid" ] && echo yes)" "yes"
check "active right after the transaction (the old %preun didn't stop it)" "$(rocky 'systemctl is-active flawrook-agent || true')" "active"
check "still enabled" "$(rocky 'systemctl is-enabled flawrook-agent || true')" "enabled"
check "it runs the binary on disk, not the replaced one" "$(rocky "readlink /proc/$new/exe || true")" "/usr/bin/flawrook-agent"
exit $fail
