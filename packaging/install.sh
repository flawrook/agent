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

# Installs the FlawRook agent. In one line:
#   curl -fsSL https://github.com/flawrook/agent/releases/latest/download/install.sh | sudo env FLAWROOK_URL=<origin> FLAWROOK_TOKEN=flra_… sh
# Or in two steps, which keeps the token out of shell history: write url and token to
# /etc/flawrook/agent.yaml yourself, then run this script without FLAWROOK_TOKEN. It gives /etc/flawrook and
# its files to root and the flawrook group (0750, 0640), which the service reads them through.
#
# It installs this release's deb (Debian, Ubuntu), rpm (Red Hat, Rocky Linux, AlmaLinux) or plain binary,
# each checked against the release's checksums.txt before it is used. Where systemd is installed, it needs
# systemd 235 or newer (Debian 10, Ubuntu 18.04, RHEL 8 and later), and installs nothing on an older one.
# The token goes into /etc/flawrook/agent.yaml only, never into the systemd unit or its environment, and the
# service starts only once a token is set. FLAWROOK_RELEASE_URL points at another copy of the release (a mirror,
# a test).
set -eu

VERSION=@VERSION@
CONFIG=/etc/flawrook/agent.yaml

fail() {
  echo "flawrook-agent install: $*" >&2
  exit 1
}

# Signing comes with the first public release: verify checksums.txt's signature here (cosign
# verify-blob) before any checksum in it is trusted.
verify_signature() { :; }

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    fail "neither curl nor wget is installed"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# get downloads one file of the release into $tmp and checks it against checksums.txt.
get() {
  fetch "$release/$1" "$tmp/$1"
  want=$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")
  [ -n "$want" ] || fail "$1 isn't in the release's checksums.txt"
  got=$(sha256 "$tmp/$1")
  [ "$got" = "$want" ] || fail "$1: sha256 $got, but checksums.txt says $want"
}

# The flawrook group reads the config with root: the service is a member (SupplementaryGroups=flawrook) and needs
# no capability for it. Like most packages' groups, it stays when the agent is removed.
ensure_group() {
  grep -q '^flawrook:' /etc/group && return 0
  if command -v groupadd >/dev/null 2>&1; then groupadd --system flawrook; else addgroup -S flawrook; fi
}

# set_modes gives /etc/flawrook and the files in it to root and the flawrook group (0750, 0640), after every
# write, so none leaves the service unable to read its config.
set_modes() {
  [ -d /etc/flawrook ] || return 0
  chgrp flawrook /etc/flawrook && chmod 0750 /etc/flawrook
  for f in /etc/flawrook/*; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then chgrp flawrook "$f" && chmod 0640 "$f"; fi
  done
}

# write_config puts the given url and token into agent.yaml (0600), keeps its other keys, and keeps the
# previous file as agent.yaml.bak.
write_config() {
  [ -n "$url$token" ] || return 0
  install -d -m 0700 /etc/flawrook
  new=$(mktemp /etc/flawrook/.agent.yaml.XXXXXX)
  if [ -f "$CONFIG" ]; then
    drop=""
    [ -z "$url" ] || drop="url"
    [ -z "$token" ] || drop="${drop:+$drop|}token"
    grep -Ev "^[[:space:]]*($drop)[[:space:]]*:" "$CONFIG" >"$new" || true
    cp -p "$CONFIG" "$CONFIG.bak"
  fi
  [ -z "$url" ] || echo "url: $url" >>"$new"
  [ -z "$token" ] || echo "token: $token" >>"$new"
  chmod 0600 "$new"
  chgrp flawrook "$new" && chmod 0640 "$new"
  mv "$new" "$CONFIG"
  set_modes
}

has_token() { grep -Eq '^token:[[:space:]]*[^[:space:]#]' "$CONFIG" 2>/dev/null; }
# The service's current run (empty when it has none, or without systemd): a new one after the package step
# means the package's postinstall has already started it.
run_id() { systemctl show -p InvocationID --value flawrook-agent.service 2>/dev/null || true; }
# systemd's version from the first line of systemctl --version ("systemd 252 (252.22-1~deb12u1)"), or nothing.
systemd_version() { systemctl --version 2>/dev/null | awk 'NR == 1 && $1 == "systemd" && $2 ~ /^[0-9]/ { sub(/[^0-9].*/, "", $2); print $2 }'; }

main() {
  # The input first, as the agent will read it: https, or plain http only to this machine.
  url=${FLAWROOK_URL:-}
  token=${FLAWROOK_TOKEN:-}
  case "$token" in *[!A-Za-z0-9_-]*) fail "FLAWROOK_TOKEN has a character no token has; copy it again from FlawRook" ;; esac
  case "$url" in *[[:space:]\"\'\\]*) fail "FLAWROOK_URL has a space, a quote or a backslash" ;; esac
  case "$url" in
    "" | https://?* | http://localhost | http://localhost[:/]* | http://127.0.0.1 | http://127.0.0.1[:/]* | "http://[::1]" | "http://[::1]"[:/]*) ;;
    *) fail "FLAWROOK_URL must start with https:// (plain http only to localhost, 127.0.0.1 or [::1])" ;;
  esac
  [ "$(id -u)" = 0 ] || fail "run it as root (sudo)"
  [ "$(uname -s)" = Linux ] || fail "the agent runs on Linux only"
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 rpmarch=x86_64 ;;
    aarch64 | arm64) arch=arm64 rpmarch=aarch64 ;;
    *) fail "no build for $(uname -m)" ;;
  esac
  # The agent's sandbox needs systemd 235 or newer: before 232 systemd ignores DynamicUser=, and the agent would
  # run as root. Where systemctl is installed, an older version, or one it can't read, stops here.
  if command -v systemctl >/dev/null 2>&1; then
    v=$(systemd_version) need="the agent needs systemd 235 or newer, so its sandbox (DynamicUser) works. Not installing."
    [ -n "$v" ] || fail "systemctl --version names no systemd version; $need"
    [ "$v" -ge 235 ] || fail "systemd $v found; $need"
  fi

  release=${FLAWROOK_RELEASE_URL:-https://github.com/flawrook/agent/releases/download/v$VERSION}
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  fetch "$release/checksums.txt" "$tmp/checksums.txt"
  verify_signature "$tmp/checksums.txt"

  # The group and the config first: a package's postinstall starts the service when it finds a token.
  ensure_group
  write_config
  run_before=$(run_id) pkg=

  if command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    pkg=deb
    get "flawrook-agent-$arch.deb"
    # confold: an agent.yaml written before the package (the two-step form) stays as it is.
    dpkg -i --force-confdef --force-confold "$tmp/flawrook-agent-$arch.deb" >/dev/null
    bin=/usr/bin/flawrook-agent
  elif command -v rpm >/dev/null 2>&1 && { command -v dnf || command -v yum; } >/dev/null 2>&1; then
    pkg=rpm
    get "flawrook-agent-$rpmarch.rpm"
    rpm -U --replacepkgs --quiet "$tmp/flawrook-agent-$rpmarch.rpm"
    bin=/usr/bin/flawrook-agent
  else
    get "flawrook-agent-linux-$arch"
    install -m 0755 "$tmp/flawrook-agent-linux-$arch" /usr/local/bin/flawrook-agent
    bin=/usr/local/bin/flawrook-agent
    if [ -d /run/systemd/system ]; then
      get flawrook-agent.service
      sed "s#/usr/bin/flawrook-agent#$bin#" "$tmp/flawrook-agent.service" >/etc/systemd/system/flawrook-agent.service
    fi
    [ -f "$CONFIG" ] || { install -d -m 0750 /etc/flawrook && install -m 0640 /dev/null "$CONFIG"; }
  fi
  set_modes # 0.1.0 left /etc/flawrook root's alone (0700, 0600)
  echo "flawrook-agent $VERSION installed: $bin"

  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable flawrook-agent.service >/dev/null 2>&1
    if has_token; then
      # The deb or rpm's postinstall (re)started it with this config, on an install and on an upgrade alike;
      # a second restart would only start it twice. The plain binary, or a service that isn't running, starts here.
      if [ -z "$pkg" ] || ! systemctl is-active --quiet flawrook-agent.service || [ "$(run_id)" = "$run_before" ]; then
        systemctl restart flawrook-agent.service
      fi
      echo "Started. Its log: journalctl -u flawrook-agent"
    else
      echo "Next: write url and token to $CONFIG (mode 0600), then run: systemctl start flawrook-agent"
    fi
  else
    echo "No systemd here: run $bin from your init system, as root or as a user in the flawrook group."
    has_token || echo "It reads url and token from $CONFIG (root and the flawrook group, mode 0640)."
  fi
}

main "$@"
