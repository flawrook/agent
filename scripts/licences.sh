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

# Collects the licence files of every Go module compiled into the agent (linux amd64 and arm64), and of
# the Go runtime, into third_party/licenses/<module path>/, as each ships them; fails when a linked module
# has none. --check changes nothing and fails when third_party/licenses is out of date (release.sh runs it).
# Docker only, with the module cache volume scripts/docker-go.sh uses.
set -eu
GO_IMAGE=golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61
cd "$(dirname "$0")/.."
exec docker run --rm --label org.flawrook.agent=build -v "$PWD":/src -w /src \
  -v flawrook-agent-gomod:/go/pkg/mod -v flawrook-agent-gocache:/root/.cache/go-build \
  -e CGO_ENABLED=0 -e MODE="${1:-}" "$GO_IMAGE" sh -eu -c '
  list() { GOOS=linux GOARCH=$1 go list -deps -f "{{with .Module}}{{.Path}}@{{.Version}} {{.Dir}}{{end}}" ./cmd/flawrook-agent; }
  mods=$({ list amd64; list arm64; } | grep -v "^flawrook.dev/agent@" | sort -u)
  out=$(mktemp -d)
  mkdir -p "$out/go"
  cp "$(go env GOROOT)/LICENSE" "$out/go/LICENSE"
  missing=""
  echo "$mods" | { while read -r m dir; do
    files=$(ls "$dir" | grep -iE "^(licen[cs]e|copying|notice|unlicense)([-._].*)?$" | grep -viE "\.(go|s|c|h)$" || true)
    if [ -z "$files" ]; then echo "$m" >>"$out.missing"; continue; fi
    mkdir -p "$out/${m%@*}"
    for f in $files; do cp "$dir/$f" "$out/${m%@*}/$f"; done
  done; }
  if [ -s "$out.missing" ]; then echo "no licence file in: $(tr "\n" " " <"$out.missing")" >&2; exit 1; fi
  count=$(echo "$mods" | wc -l)
  if [ "$MODE" = --check ]; then
    if ! diff -r "$out" third_party/licenses >/dev/null 2>&1; then
      echo "third_party/licenses is out of date; run scripts/licences.sh" >&2
      diff -rq "$out" third_party/licenses >&2 || true
      exit 1
    fi
    echo "third_party/licenses: $count modules and the Go runtime, up to date"
  else
    rm -r third_party/licenses
    cp -R "$out" third_party/licenses
    echo "third_party/licenses: $count modules and the Go runtime"
  fi
'
