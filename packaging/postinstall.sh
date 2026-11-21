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

# deb and rpm: enable the service; start it (or restart it after an upgrade) only once a token is set.
set -e
# The config is root's and the flawrook group's to read (0.2.0). Before, it was root's alone (0700 and 0600),
# and an unchanged agent.yaml may come back with the package's modes: set them on every install and upgrade.
chgrp flawrook /etc/flawrook && chmod 0750 /etc/flawrook
for f in /etc/flawrook/*; do
  if [ -f "$f" ] && [ ! -L "$f" ]; then chgrp flawrook "$f" && chmod 0640 "$f"; fi
done
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || exit 0
# The agent's sandbox needs systemd 235 or newer: before 232 systemd ignores DynamicUser=, and the agent would run
# as root. With an older version, or one this can't read, the files stay installed and the service stays off.
v=$(systemctl --version 2>/dev/null | awk 'NR == 1 && $1 == "systemd" && $2 ~ /^[0-9]/ { sub(/[^0-9].*/, "", $2); print $2 }')
need="the agent needs systemd 235 or newer, so its sandbox (DynamicUser) works. Installed, but not enabled or started."
[ -n "$v" ] || { echo "flawrook-agent: systemctl --version names no systemd version; $need" >&2; exit 0; }
[ "$v" -ge 235 ] || { echo "flawrook-agent: systemd $v found; $need" >&2; exit 0; }
systemctl daemon-reload
systemctl enable flawrook-agent.service >/dev/null 2>&1 || true
if grep -Eq '^token:[[:space:]]*[^[:space:]#]' /etc/flawrook/agent.yaml 2>/dev/null; then
  systemctl restart flawrook-agent.service
else
  echo "flawrook-agent: set url and token in /etc/flawrook/agent.yaml, then run: systemctl start flawrook-agent"
fi
