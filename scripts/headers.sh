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

# Checks the Apache-2.0 header (scripts/license-header.txt) at the top of every Go, shell and Python file, or
# with --fix writes it, replacing an older one. The copyright holder is in that template and in NOTICE
# only: to change it, edit both and run scripts/headers.sh --fix.
# The body is one function, read whole before it runs: --fix may rewrite this very file.
set -eu
main() {
cd "$(dirname "$0")/.."
fix=${1:-}
status=0
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
for f in $(find . \( -path ./dist -o -path ./third_party \) -prune -o \( -name '*.go' -o -name '*.sh' -o -name '*.py' -o -name nfpm.yaml \) -print | LC_ALL=C sort); do
  case "$f" in *.go) c='//' ;; *) c='#' ;; esac
  awk -v c="$c" -v tmpl=scripts/license-header.txt '
    BEGIN { while ((getline l < tmpl) > 0) h = h c (l == "" ? "" : " " l) "\n"; state = "start" }
    NR == 1 && /^#!/ { out = $0 "\n"; next }
    state == "start" {
      if (index($0, c " Copyright ") == 1) { state = "header"; next }
      out = out h "\n"; state = "body"
    }
    state == "header" { if ($0 == c " limitations under the License.") state = "after"; next }
    state == "after" { out = out h "\n"; state = "body"; if ($0 == "") next }
    { out = out $0 "\n" }
    END { if (state != "body") out = out h; printf "%s", out }
  ' "$f" >"$tmp"
  if ! cmp -s "$tmp" "$f"; then
    if [ "$fix" = --fix ]; then cat "$tmp" >"$f"; echo "header written: $f"; else echo "header missing or outdated: $f"; status=1; fi
  fi
done
exit $status
}
main "$@"
