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

# deb and rpm, before the files are unpacked: the flawrook group, which owns /etc/flawrook with root. The
# service (a user of its own, SupplementaryGroups=flawrook) reads its config through it, with no capability.
# The group stays on removal, as most packages leave theirs.
set -e
grep -q '^flawrook:' /etc/group || groupadd --system flawrook
