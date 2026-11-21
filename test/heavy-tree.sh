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

# The file-heavy host's trees for integration.sh (0.2.0, the review's memory finding), generated in the
# container at run time, never baked into an image: about 310,000 files with the names and depths of real
# trees. Every package.json and 50 METADATA files have a small valid body, as on a real host; the rest are
# empty. Syft's index holds paths and metadata, not contents, so empty files cost it what real ones do, and
# the disk only inodes and directories.
#   /home/dev/shop/node_modules   120,000  (3,000 packages)  outside what 0.2.0 reads
#   /srv/api/node_modules          60,000  (1,500)            outside
#   /var/www/html                  10,000                     outside
#   /usr/src/linux-6.12            80,000                     outside
#   /opt/app/node_modules          30,000  (750)              inside /opt: the **/node_modules exclusion
#   /opt/venv/.../site-packages    10,000                     inside /opt: the **/site-packages exclusion
# Usage: gen.sh [remove]
set -eu
TREES="/home/dev/shop /srv/api /var/www/html /usr/src/linux-6.12 /opt/app /opt/venv"
# shellcheck disable=SC2086 # TREES is one word per tree, here and below
if [ "${1:-}" = remove ]; then rm -rf $TREES; exit 0; fi
modules() { # dir, packages: 40 files each, as an npm package lays them out
  i=0
  while [ "$i" -lt "$2" ]; do
    p="$1/node_modules/@scope-$((i % 50))/package-name-$i"
    mkdir -p "$p/lib/internal" "$p/dist/esm" "$p/types"
    (cd "$p" && touch package.json README.md LICENSE CHANGELOG.md index.js index.d.ts \
      lib/a.js lib/b.js lib/c.js lib/d.js lib/e.js lib/f.js lib/g.js lib/h.js lib/i.js lib/j.js \
      lib/internal/a.js lib/internal/b.js lib/internal/c.js lib/internal/d.js lib/internal/e.js lib/internal/f.js \
      dist/esm/a.mjs dist/esm/b.mjs dist/esm/c.mjs dist/esm/d.mjs dist/esm/e.mjs dist/esm/f.mjs dist/esm/g.mjs dist/esm/h.mjs \
      types/a.d.ts types/b.d.ts types/c.d.ts types/d.d.ts types/e.d.ts types/f.d.ts types/g.d.ts types/h.d.ts types/i.d.ts types/j.d.ts)
    printf '{"name":"package-name-%s","version":"1.0.0"}\n' "$i" >"$p/package.json"
    i=$((i + 1))
  done
}
flat() { # dir, directories, files each, suffix
  dir=$1 dirs=$2 files=$3 suffix=$4 # set -- below takes the positional parameters
  i=0
  while [ "$i" -lt "$dirs" ]; do
    p="$dir/sub-$((i % 40))/dir-$i"
    mkdir -p "$p"
    j=0
    set --
    while [ "$j" -lt "$files" ]; do set -- "$@" "file_$j.$suffix"; j=$((j + 1)); done
    (cd "$p" && touch "$@")
    i=$((i + 1))
  done
}
modules /home/dev/shop 3000
modules /srv/api 1500
flat /var/www/html 200 50 php
flat /usr/src/linux-6.12 2000 40 c
modules /opt/app 750
flat /opt/venv/lib/python3.13/site-packages 250 40 py
i=0
while [ "$i" -lt 50 ]; do # a few installed distributions' metadata
  d=/opt/venv/lib/python3.13/site-packages/dist_$i-1.0.0.dist-info
  mkdir -p "$d"
  printf 'Metadata-Version: 2.1\nName: dist-%s\nVersion: 1.0.0\n' "$i" >"$d/METADATA"
  i=$((i + 1))
done
# shellcheck disable=SC2086
find $TREES -type f | wc -l
# shellcheck disable=SC2086
du -sh $TREES 2>/dev/null | tr '\t' ' '
