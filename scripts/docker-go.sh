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

# Runs the Go toolchain in Docker, so nothing is installed on the machine. Examples:
#   scripts/docker-go.sh test ./...
#   GOARCH=amd64 scripts/docker-go.sh build -o dist/flawrook-agent-linux-amd64 ./cmd/flawrook-agent
# The image is pinned by digest (golang:1.27.2-bookworm, built 2026-10-08). GO_MEMORY caps the container's memory
# (default 3g); GO_CPUS, when set, caps its CPUs (unset: no cap, as the release gate runs).
set -eu
GO_IMAGE=golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61
cd "$(dirname "$0")/.."
exec docker run --rm --label org.flawrook.agent=build --memory "${GO_MEMORY:-3g}" --memory-swap "${GO_MEMORY:-3g}" ${GO_CPUS:+--cpus "$GO_CPUS"} \
  -v "$PWD":/src -w /src \
  -v flawrook-agent-gomod:/go/pkg/mod -v flawrook-agent-gocache:/root/.cache/go-build \
  -e CGO_ENABLED=0 -e GOFLAGS=-trimpath ${GOOS:+-e GOOS=$GOOS} ${GOARCH:+-e GOARCH=$GOARCH} \
  "$GO_IMAGE" go "$@"
